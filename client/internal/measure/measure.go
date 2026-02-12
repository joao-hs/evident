package measure

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/diskfs/go-diskfs"
	"github.com/diskfs/go-diskfs/backend/file"
	"github.com/diskfs/go-diskfs/partition/gpt"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
)

/*
 * This code assumes the VM's UEFI where this VM image will be running on is based on OVMF, which:
 * - First, measures into PCR4 a boot attempt with a string tag. We should only see one appearance of that measurement
 * - Second, measures into PCR4 a separator event. Marks the transition between pre-boot and post-boot environments
 * Both measure little to no information about the underlying running software. It's okay since the third PCR4 measurement and PCR11's measurements give us
 * the measurements we need.
 */

var (
	pcr4FirstMeasuredArtifact  = []byte("Calling EFI Application from Boot Option") // source: https://github.com/tianocore/edk2/blob/12f785f106216eedbedb02427255e257d506367f/OvmfPkg/Tcg/TdTcg2Dxe/TdTcg2Dxe.c#L2110-L2116
	pcr4SecondMeasuredArtifact = []byte{0x00, 0x00, 0x00, 0x00}                     // source: https://github.com/tianocore/edk2/blob/12f785f106216eedbedb02427255e257d506367f/OvmfPkg/Tcg/TdTcg2Dxe/TdTcg2Dxe.c#L2121-L2131
)

var (
	pcr4FirstMeasurementSha1   = sha1.Sum(pcr4FirstMeasuredArtifact)
	pcr4FirstMeasurementSha256 = sha256.Sum256(pcr4FirstMeasuredArtifact)
	pcr4FirstMeasurementSha384 = sha512.Sum384(pcr4FirstMeasuredArtifact)
	pcr4FirstMeasurementSha512 = sha512.Sum512(pcr4FirstMeasuredArtifact)
)

var (
	pcr4SecondMeasurementSha1   = sha1.Sum(pcr4SecondMeasuredArtifact)
	pcr4SecondMeasurementSha256 = sha256.Sum256(pcr4SecondMeasuredArtifact)
	pcr4SecondMeasurementSha384 = sha512.Sum384(pcr4SecondMeasuredArtifact)
	pcr4SecondMeasurementSha512 = sha512.Sum512(pcr4SecondMeasuredArtifact)
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
	_SYSTEMD_PCRLOCK          = "systemd-pcrlock"
	_ALT_PATH_SYSTEMD_PCRLOCK = "/usr/lib/systemd/systemd-pcrlock" // usually /usr/lib/systemd/ is not in PATH

	_ESP_PARTITION_NAME       = "esp"
	_ESP_PARTITION_MOUNT_PATH = "/boot"
	_UKI_PATH_INSIDE_IMAGE    = "/boot/EFI/BOOT/BOOTX64.EFI"

	_EVIDENT_TMP_PATH = "/tmp/evident"
	_UKI_TMP_PATH     = "/tmp/evident/uki.efi"
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
		zeroOutput       domain.ExpectedPcrDigests
		pcrLockOutBuffer bytes.Buffer
		pcrLockErrBuffer bytes.Buffer
	)

	log.Get().Debugln("Creating temporary directory:", _EVIDENT_TMP_PATH)
	err := os.MkdirAll(_EVIDENT_TMP_PATH, 0755)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			log.Get().Debugln("Temporary directory already exists:", _EVIDENT_TMP_PATH)
		} else {
			return zeroOutput, fmt.Errorf("failed to create temporary directory: %v", err)
		}
	}

	extractUKI(imagePath, _ESP_PARTITION_NAME, _ESP_PARTITION_MOUNT_PATH, _UKI_PATH_INSIDE_IMAGE, _UKI_TMP_PATH)

	log.Get().Debugln("Running:", self.systemdPcrLockCmd, "lock-uki", _UKI_TMP_PATH)
	pcrLockCmd := exec.Command(self.systemdPcrLockCmd, "lock-uki", _UKI_TMP_PATH)
	pcrLockCmd.Stdout = &pcrLockOutBuffer
	pcrLockCmd.Stderr = &pcrLockErrBuffer
	err = pcrLockCmd.Run()
	if err != nil {
		return zeroOutput, fmt.Errorf("systemd-pcrlock command failed: %v: %s", err, pcrLockErrBuffer.String())
	}

	var output domain.ExpectedPcrDigests
	err = json.Unmarshal(pcrLockOutBuffer.Bytes(), &output)
	if err != nil {
		return zeroOutput, err
	}

	// PCR 4 has two well known measurements before the predicted measurement given by the pcr-lock command
	output.Records = append([]struct {
		Pcr     int "json:\"pcr\""
		Digests []struct {
			HashAlg string "json:\"hashAlg\""
			Digest  string "json:\"digest\""
		} "json:\"digests\""
	}{
		{
			Pcr: 4,
			Digests: []struct {
				HashAlg string "json:\"hashAlg\""
				Digest  string "json:\"digest\""
			}{
				{
					HashAlg: domain.HashAlgorithm(domain.ENUM_HASH_ALGORITHM_SHA1).String(),
					Digest:  hex.EncodeToString(pcr4FirstMeasurementSha1[:]),
				},
				{
					HashAlg: domain.HashAlgorithm(domain.ENUM_HASH_ALGORITHM_SHA256).String(),
					Digest:  hex.EncodeToString(pcr4FirstMeasurementSha256[:]),
				},
				{
					HashAlg: domain.HashAlgorithm(domain.ENUM_HASH_ALGORITHM_SHA384).String(),
					Digest:  hex.EncodeToString(pcr4FirstMeasurementSha384[:]),
				},
				{
					HashAlg: domain.HashAlgorithm(domain.ENUM_HASH_ALGORITHM_SHA512).String(),
					Digest:  hex.EncodeToString(pcr4FirstMeasurementSha512[:]),
				},
			},
		}, {
			Pcr: 4,
			Digests: []struct {
				HashAlg string "json:\"hashAlg\""
				Digest  string "json:\"digest\""
			}{
				{
					HashAlg: domain.HashAlgorithm(domain.ENUM_HASH_ALGORITHM_SHA1).String(),
					Digest:  hex.EncodeToString(pcr4SecondMeasurementSha1[:]),
				},
				{
					HashAlg: domain.HashAlgorithm(domain.ENUM_HASH_ALGORITHM_SHA256).String(),
					Digest:  hex.EncodeToString(pcr4SecondMeasurementSha256[:]),
				},
				{
					HashAlg: domain.HashAlgorithm(domain.ENUM_HASH_ALGORITHM_SHA384).String(),
					Digest:  hex.EncodeToString(pcr4SecondMeasurementSha384[:]),
				},
				{
					HashAlg: domain.HashAlgorithm(domain.ENUM_HASH_ALGORITHM_SHA512).String(),
					Digest:  hex.EncodeToString(pcr4SecondMeasurementSha512[:]),
				},
			},
		},
	}, output.Records...)

	return output, nil
}

func (self *vmImageMeasurer) GetEquivalentCommands(imagePath string, outputFile string) string {
	output := strings.Builder{}
	fmt.Fprintf(&output, "mkdir -p %s 1>/dev/null 2>&1 && ", filepath.Dir(_UKI_TMP_PATH))
	fmt.Fprintf(&output, "sudo %s --copy-from %s %s > %s && ", self.systemdDissectCmd, imagePath, _UKI_PATH_INSIDE_IMAGE, _UKI_TMP_PATH)
	fmt.Fprintf(&output, "%s lock-uki %s", self.systemdPcrLockCmd, _UKI_TMP_PATH)
	if outputFile != "" {
		fmt.Fprintf(&output, " > %s", outputFile)
	}
	return output.String()
}

func extractUKI(imagePath string, ukiPartitionName string, ukiPartitionMountedAt string, ukiPathInsideImage string, outUkiFile string) error {
	imageFile, err := os.DirFS(filepath.Dir(imagePath)).Open(filepath.Base(imagePath))
	if err != nil {
		return err
	}

	fileBackend := file.New(imageFile, true)
	disk, err := diskfs.OpenBackend(fileBackend, diskfs.WithOpenMode(diskfs.OpenModeOption(diskfs.ReadOnly)))
	if err != nil {
		return err
	}

	table, err := disk.GetPartitionTable()
	if err != nil {
		return err
	}

	partitions := table.GetPartitions()
	if len(partitions) < 1 {
		return fmt.Errorf("no partitions found in given disk image")
	}

	espPartition := -1
	for i, partition := range partitions {
		gptPartition, ok := partition.(*gpt.Partition)
		if !ok {
			continue
		}
		if gptPartition.Name == ukiPartitionName {
			espPartition = i
			break
		}
	}
	if espPartition == -1 {
		return fmt.Errorf("%s partition not found", ukiPartitionName)
	}

	fs, err := disk.GetFilesystem(espPartition + 1) // 1-indexed; 0 has special effect
	if err != nil {
		return err
	}

	ukiRelativePath, err := filepath.Rel(ukiPartitionMountedAt, ukiPathInsideImage)
	if err != nil {
		return fmt.Errorf("unexcepted uki location; not under %s", ukiPartitionMountedAt)
	}

	ukiRelativePath = fmt.Sprintf("/%s", ukiRelativePath)

	f, err := fs.OpenFile(ukiRelativePath, os.O_RDONLY)
	if err != nil {
		return err
	}
	defer f.Close()

	out, err := os.Create(outUkiFile)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, f)
	if err != nil {
		return err
	}

	return nil
}
