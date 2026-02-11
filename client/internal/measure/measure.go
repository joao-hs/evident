package measure

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
)

type VMImageMeasurer interface {
	MeasureImage(imagePath string) (domain.ExpectedPcrDigests, error)
	GetEquivalentCommands(imagePath string, outputFile string) string
}

type vmImageMeasurer struct {
	systemdDissectCmd string
	systemdPcrLockCmd string
}

const (
	_SYSTEMD_DISSECT          = "systemd-dissect"
	_SYSTEMD_PCRLOCK          = "systemd-pcrlock"
	_ALT_PATH_SYSTEMD_PCRLOCK = "/usr/lib/systemd/systemd-pcrlock" // usually /usr/lib/systemd/ is not in PATH
	_UKI_PATH_INSIDE_IMAGE    = "/boot/EFI/BOOT/BOOTX64.EFI"
	_EVIDENT_TMP_PATH         = "/tmp/evident"
	_UKI_TMP_PATH             = "/tmp/evident/uki.efi"
)

var (
	jqQuery string
)

func NewVMImageMeasurer() (VMImageMeasurer, error) {
	self := &vmImageMeasurer{
		systemdDissectCmd: "",
		systemdPcrLockCmd: "",
	}

	if err := self.checkRequiredExternalCommands(); err != nil {
		return nil, err
	}
	return self, nil
}

func (self *vmImageMeasurer) checkRequiredExternalCommands() error {
	var err error

	self.systemdDissectCmd, err = exec.LookPath(_SYSTEMD_DISSECT)
	if err != nil {
		return fmt.Errorf("`systemd-dissect` command is not present in PATH; might need to install 'systemd-container' package")
	}

	self.systemdPcrLockCmd, err = exec.LookPath(_SYSTEMD_PCRLOCK)
	if err != nil {
		self.systemdPcrLockCmd, err = exec.LookPath(_ALT_PATH_SYSTEMD_PCRLOCK)
		if err == nil {
			return nil
		}
		return fmt.Errorf("`systemd-pcrlock` command is not present in PATH; might need to install 'systemd' package and/or add /usr/lib/systemd/ to PATH")
	}

	return nil
}

func (self *vmImageMeasurer) MeasureImage(imagePath string) (domain.ExpectedPcrDigests, error) {
	var (
		zeroOutput   domain.ExpectedPcrDigests
		dissectOutBuffer bytes.Buffer
		dissectErrBuffer bytes.Buffer
		pcrLockOutBuffer bytes.Buffer
		pcrLockErrBuffer bytes.Buffer
	)

	log.Get().Warnln("Running as sudo:", self.systemdDissectCmd, "--copy-from", imagePath, _UKI_PATH_INSIDE_IMAGE)
	dissectCmd := exec.Command("sudo", self.systemdDissectCmd, "--copy-from", imagePath, _UKI_PATH_INSIDE_IMAGE)
	dissectCmd.Stdin = os.Stdin // in case sudo needs password input
	dissectCmd.Stdout = &dissectOutBuffer
	dissectCmd.Stderr = &dissectErrBuffer
	err := dissectCmd.Run()
	if err != nil {
		return zeroOutput, fmt.Errorf("systemd-dissect command failed: %v: %s", err, dissectErrBuffer.String())
	}

	log.Get().Debugln("Creating temporary directory:", _EVIDENT_TMP_PATH)
	err = os.MkdirAll(_EVIDENT_TMP_PATH, 0755)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			log.Get().Debugln("Temporary directory already exists:", _EVIDENT_TMP_PATH)
		} else {
			return zeroOutput, fmt.Errorf("failed to create temporary directory: %v", err)
		}
	}

	log.Get().Debugln("Writing UKI to temporary path:", _UKI_TMP_PATH)
	err = os.WriteFile(_UKI_TMP_PATH, dissectOutBuffer.Bytes(), 0644)
	if err != nil {
		return zeroOutput, fmt.Errorf("failed to write UKI to temporary path: %v", err)
	}

	log.Get().Debugln("Running:", self.systemdPcrLockCmd, "lock-uki", _UKI_TMP_PATH)
	pcrLockCmd := exec.Command(self.systemdPcrLockCmd, "lock-uki", _UKI_TMP_PATH)
	pcrLockCmd.Stdout = &pcrLockOutBuffer
	pcrLockCmd.Stderr = &pcrLockErrBuffer
	err = pcrLockCmd.Run()
	if err != nil {
		return zeroOutput, fmt.Errorf("systemd-pcrlock command failed: %v: %s", err, pcrLockErrBuffer.String())
	}

	var pcrLockOutput struct {
		Records []struct {
			PCR     int `json:"pcr"`
			Digests []struct {
				HashAlg string `json:"hashAlg"`
				Digest  string `json:"digest"`
			} `json:"digests"`
		} `json:"records"`
	}

	err = json.Unmarshal(pcrLockOutBuffer.Bytes(), &pcrLockOutput)
	if err != nil {
		return zeroOutput, err
	}

	measures := make(map[int]string)

	// PCR 12 must be asserted to 0x0 since it measures UKI section overwrites and addons that may change
	// expected behavior of the UKI.
	measures[12] = "0000000000000000000000000000000000000000000000000000000000000000" // sha256-sized (32 bytes) hex represented

	// we want the last sha256 digest for each PCR
	for _, record := range pcrLockOutput.Records {
		for _, digest := range record.Digests {
			if digest.HashAlg == "sha256" {
				measures[record.PCR] = digest.Digest
				break
			}
		}
	}

	output := domain.ExpectedPcrDigests{}
	for pcrIndex, digest := range measures {
		output.SetDigestAtIndex(pcrIndex, digest)
	}

	return output, nil
}

func (self *vmImageMeasurer) GetEquivalentCommands(imagePath string, outputFile string) string {
	output := strings.Builder{}
	fmt.Fprintf(&output, "mkdir -p %s 1>/dev/null 2>&1 && ", filepath.Dir(_UKI_TMP_PATH))
	fmt.Fprintf(&output, "sudo %s --copy-from %s %s > %s && ", self.systemdDissectCmd, imagePath, _UKI_PATH_INSIDE_IMAGE, _UKI_TMP_PATH)
	fmt.Fprintf(&output, "%s lock-uki %s | jq '%s'", self.systemdPcrLockCmd, _UKI_TMP_PATH, jqQuery)
	if outputFile != "" {
		fmt.Fprintf(&output, " > %s", outputFile)
	}
	return output.String()
}

func init() {
	// `systemd-pcrlock` outputs a json with a single field, "records", which has an array of
	// JSON objects like this:
	// {
	//   "pcr": 4,
	//   "digests": [
	//     ...
	//     {
	//       "hashAlg": "sha256",
	//       "digest": "..."
	//     }
	//     ...
	//   ]
	// }
	// The records order is relevant, as this is supposed to replicate the tpm eventlog
	// Therefore, we want the last record of each different PCR, and only the relevant algorithm: sha256

	jqQueryBuilder := strings.Builder{}
	jqQueryBuilder.WriteString("[")

	jqQueryBuilder.WriteString(".records | ")
	jqQueryBuilder.WriteString("group_by(.pcr) | ")
	jqQueryBuilder.WriteString(".[] | ")
	jqQueryBuilder.WriteString("last | ")

	jqQueryBuilder.WriteString("{ ")
	jqQueryBuilder.WriteString("pcr: .pcr, ")
	jqQueryBuilder.WriteString("digest: ( ")
	jqQueryBuilder.WriteString(".digests[] | ")
	jqQueryBuilder.WriteString("select(.hashAlg == \"sha256\").digest ")
	jqQueryBuilder.WriteString(") ")
	jqQueryBuilder.WriteString("} ")

	jqQueryBuilder.WriteString("] + [ ")

	// Additionally, the expected value for PCR 12 should be 0x0, because it measures overwrites to parts of
	// the UKI sections and other addons that may change the expected behavior of the UKI.

	jqQueryBuilder.WriteString("{ ")
	jqQueryBuilder.WriteString("pcr: 12, ")
	jqQueryBuilder.WriteString("digest: \"0000000000000000000000000000000000000000000000000000000000000000\" ")
	jqQueryBuilder.WriteString("} ")

	jqQueryBuilder.WriteString("]")

	// The output of the jq query will be like:
	// [
	//   {
	//     "pcr": 4,
	//     "digest": "7fcf06c1c15cb8dfc6dbde0de2db285b1e66ee260575fa0d75ee6bc91157ce50"
	//   },
	//   {
	//     "pcr": 11,
	//     "digest": "3e85f29ac1df8b1643c5c97166248f53177d009ee68a77e6be20b7d7d295288e"
	//   },
	//   {
	//     "pcr": 12,
	//     "digest": "0000000000000000000000000000000000000000000000000000000000000000"
	//   }
	// ]

	jqQuery = jqQueryBuilder.String()
}
