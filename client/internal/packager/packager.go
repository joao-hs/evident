package packager

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/build"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/measure"
)

type Packager interface {
	GetEquivalentCommands(flakePath string, variation string, outputDirPath string) string
	Package(flakePath string, variation string, outputDirPath string, repoUrl string, commitHash string) error
}

type packager struct {
	vmImageBuilder  build.VMImageBuilder
	vmImageMeasurer measure.VMImageMeasurer
	keyId           string
	nixCmd          string
	gpgCmd          string
}

func NewPackager(vmImageBuilder build.VMImageBuilder, vmImageMeasurer measure.VMImageMeasurer, keyId string) (Packager, error) {
	self := &packager{
		vmImageBuilder:  vmImageBuilder,
		vmImageMeasurer: vmImageMeasurer,
	}

	if err := self.checkRequiredExternalCommands(); err != nil {
		return nil, err
	}

	if keyId != "" {
		self.keyId = keyId
	} else {
		var err error
		self.keyId, err = self.tryGetKeyId()
		if err != nil {
			return nil, err
		}
	}

	return self, nil
}

func (self *packager) checkRequiredExternalCommands() error {
	var err error

	self.nixCmd, err = exec.LookPath("nix")
	if err != nil {
		return fmt.Errorf("`nix` command is not present in PATH")
	}

	self.gpgCmd, err = exec.LookPath("gpg")
	if err != nil {
		return fmt.Errorf("`gpg` command is not present in PATH")
	}

	return nil
}

func (self *packager) tryGetKeyId() (string, error) {
	// 1. If there is only one key, use it
	keys, err := self.listSecretKeyIDs()
	if err != nil {
		return "", err
	}

	if len(keys) == 1 {
		return keys[0], nil
	}

	// 2. Fail otherwise
	if len(keys) == 0 {
		return "", fmt.Errorf("no GPG secret keys found: run 'gpg --full-generate-key'")
	}

	return "", fmt.Errorf("multiple GPG secret keys found: specify which key to use with flag '--key'")
}

func (self *packager) GetEquivalentCommands(flakePath string, variation string, outputDirPath string) string {
	output := strings.Builder{}
	// TODO

	return output.String()
}

func (self *packager) Package(flakePath string, variation string, outputDirPath string, repoUrl string, commitHash string) error {
	var err error

	tmpOutputDirPath := "/tmp/evident-packaging-output" + fmt.Sprintf("%d", os.Getpid())

	err = os.MkdirAll(tmpOutputDirPath, 0755)
	if err != nil {
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("failed to create temporary directory: %v", err)
		}
	}

	// 1. build image to outputDirPath/disk.raw
	err = self.vmImageBuilder.BuildImage(
		flakePath,
		variation,
		filepath.Join(tmpOutputDirPath, "disk.raw"),
	)
	if err != nil {
		return err
	}

	// 2. measure image and write expected PCRs to outputDirPath/expected-pcrs.json
	expectedPcrs, err := self.vmImageMeasurer.MeasureImage(
		filepath.Join(tmpOutputDirPath, "disk.raw"),
	)
	if err != nil {
		return err
	}

	expectedPcrsBytes, err := json.MarshalIndent(expectedPcrs, "", "  ")
	if err != nil {
		return err
	}
	expectedPcrsFilePath := filepath.Join(tmpOutputDirPath, "expected-pcrs.json")
	expectedPcrsFile, err := os.OpenFile(expectedPcrsFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	_, err = io.Copy(expectedPcrsFile, bytes.NewReader(expectedPcrsBytes))
	if err != nil {
		return err
	}

	// 3. create and save manifest file to outputDirPath/MANIFEST.json

	nixVersion, err := self.getNixVersion()
	if err != nil {
		return err
	}

	imageSha256, err := getImageSha256(filepath.Join(tmpOutputDirPath, "disk.raw"))
	if err != nil {
		return err
	}

	imageFileInfo, err := os.Stat(filepath.Join(tmpOutputDirPath, "disk.raw"))
	if err != nil {
		return err
	}

	manifest := domain.Manifest{
		Version: domain.CurrentManifestVersion,
		Source: domain.ManifestSource{
			GitRepo:   repoUrl,
			GitCommit: commitHash,
		},
		Build: domain.ManifestBuild{
			NixVersion: nixVersion,
			Package:    variation,
		},
		Image: domain.ManifestImage{
			Digest:    imageSha256,
			SizeBytes: int(imageFileInfo.Size()),
		},
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}

	manifestFilePath := filepath.Join(tmpOutputDirPath, "MANIFEST.json")
	manifestFile, err := os.OpenFile(manifestFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	_, err = io.Copy(manifestFile, bytes.NewReader(manifestBytes))
	if err != nil {
		return err
	}

	// 4. sign manifest file and save the signature to outputDirPath/<signing-pub-key-id>.sig.asc
	signatureFilePath := filepath.Join(tmpOutputDirPath, fmt.Sprintf("%s.sig.asc", self.keyId))
	signCmd := exec.Command(self.gpgCmd, "--output", signatureFilePath, "--local-user", self.keyId, "--armor", "--detach-sign", manifestFilePath)
	var signStderr bytes.Buffer
	signCmd.Stdin = os.Stdin
	signCmd.Stderr = &signStderr
	err = signCmd.Run()
	if err != nil {
		return fmt.Errorf("failed to sign manifest file: %v: %s", err, signStderr.String())
	}

	/*
	 *	{tmpOutputDirPath}/
	 *	├── disk.raw
	 *	├── expected-pcrs.json
	 *	├── MANIFEST
	 *	└── <KEY_ID>.sig.asc
	 */

	// 5. move the contents of tmpOutputDirPath and save to outputDirPath/{final-pcr-digest}.package

	/*
	 *	outputDirPath/{final-pcr-digest}.package/
	 *	├── disk.raw
	 *	├── expected-pcrs.json
	 * 	├── MANIFEST
	 *	├── <KEY_ID>.sig.asc
	 *	└── package.tar.gz
	 *  	├── expected-pcrs.json
	 *  	├── MANIFEST
	 *		└── <KEY_ID>.sig.asc
	 */

	return nil
}

func (self *packager) getNixVersion() (string, error) {
	nixVersionCmd := exec.Command(self.nixCmd, "--version")
	var outBuffer bytes.Buffer
	nixVersionCmd.Stdout = &outBuffer
	err := nixVersionCmd.Run()
	if err != nil {
		return "", err
	}

	r := regexp.MustCompile(`nix \(Nix\) ([\d\.]+)`)
	matches := r.FindStringSubmatch(outBuffer.String())
	if matches == nil || len(matches) != 2 {
		return "", fmt.Errorf("could not parse nix version from output: %s", outBuffer.String())
	}
	return matches[1], nil
}

func getImageSha256(imagePath string) (string, error) {
	diskRawFile, err := os.Open(imagePath)
	if err != nil {
		return "", err
	}
	defer diskRawFile.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, diskRawFile); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func (self *packager) listSecretKeyIDs() ([]string, error) {
	cmd := exec.Command(self.gpgCmd, "--list-secret-keys", "--with-colons")

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to run gpg --list-secret-keys")
	}

	lines := strings.Split(stdout.String(), "\n")

	var keys []string

	for _, line := range lines {
		// sec:<flags>:<length>:<algo>:<keyid>:...
		if strings.HasPrefix(line, "sec:") {
			fields := strings.Split(line, ":")
			if len(fields) > 4 {
				keyID := fields[4]
				if keyID != "" {
					keys = append(keys, keyID)
				}
			}
		}
	}

	return keys, nil
}
