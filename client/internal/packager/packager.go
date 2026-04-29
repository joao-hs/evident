package packager

import (
	"bytes"
	"crypto/sha512"
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
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
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

func (p *packager) checkRequiredExternalCommands() error {
	var err error

	p.nixCmd, err = exec.LookPath("nix")
	if err != nil {
		return fmt.Errorf("`nix` command is not present in PATH")
	}
	log.Get().Debugf("using nix command at %s", p.nixCmd)

	p.gpgCmd, err = exec.LookPath("gpg")
	if err != nil {
		return fmt.Errorf("`gpg` command is not present in PATH")
	}
	log.Get().Debugf("using gpg command at %s", p.gpgCmd)

	return nil
}

func (p *packager) tryGetKeyId() (string, error) {
	// 1. If there is only one key, use it
	keys, err := p.listSecretKeyIDs()
	if err != nil {
		return "", err
	}
	log.Get().Debugf("found %d GPG secret key(s)", len(keys))

	if len(keys) == 1 {
		log.Get().Debugf("using GPG key %s", keys[0])
		return keys[0], nil
	}

	// 2. Fail otherwise
	if len(keys) == 0 {
		return "", fmt.Errorf("no GPG secret keys found: run 'gpg --full-generate-key'")
	}

	return "", fmt.Errorf("multiple GPG secret keys found: specify which key to use with flag '--key'")
}

func (p *packager) GetEquivalentCommands(flakePath string, variation string, outputDirPath string) string {
	output := strings.Builder{}
	// TODO

	return output.String()
}

func (p *packager) Package(flakePath string, variation string, outputDirPath string, repoUrl string, commitHash string) error {
	var err error

	tmpOutputDirPath := "/tmp/evident/evident-packaging-output" + fmt.Sprintf("%d", os.Getpid())
	log.Get().Debugf("using temporary packaging directory: %s", tmpOutputDirPath)

	err = os.MkdirAll(tmpOutputDirPath, 0755)
	if err != nil {
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("failed to create temporary directory: %v", err)
		}
	}

	// 1. build image to outputDirPath/disk.raw
	log.Get().Infoln("Building VM image...")
	log.Get().Debugf("build inputs: flake=%s variation=%s output=%s", flakePath, variation, filepath.Join(tmpOutputDirPath, "disk.raw"))
	err = p.vmImageBuilder.BuildImage(
		flakePath,
		variation,
		filepath.Join(tmpOutputDirPath, "disk.raw"),
	)
	if err != nil {
		return err
	}

	// 2. measure image and write expected PCRs to outputDirPath/expected-pcrs.json
	log.Get().Infoln("Measuring VM image...")
	log.Get().Debugf("measuring disk image at %s", filepath.Join(tmpOutputDirPath, "disk.raw"))
	expectedPcrs, err := p.vmImageMeasurer.MeasureImage(
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

	// 3. create and save manifest file to outputDirPath/MANIFEST
	log.Get().Infoln("Creating manifest file...")
	log.Get().Debugf("collecting manifest metadata for repo=%s commit=%s", repoUrl, commitHash)
	nixVersion, err := p.getNixVersion()
	if err != nil {
		return err
	}

	nixDerivationPath, err := p.vmImageBuilder.GetDerivationPath(flakePath, variation)
	if err != nil {
		return err
	}

	nixDerivationSha512, err := getFileSha512(nixDerivationPath)
	if err != nil {
		return err
	}
	nixDerivationFilename := filepath.Base(nixDerivationPath)
	if !strings.HasSuffix(nixDerivationFilename, ".drv") {
		return fmt.Errorf("unexpected derivation path filename: %s", nixDerivationFilename)
	}
	nixDerivationOutputName := strings.TrimSuffix(nixDerivationFilename, ".drv")
	nixDerivationPathHash := nixDerivationOutputName[:strings.Index(nixDerivationOutputName, "-")]
	nixDerivationOutputNameOnly := nixDerivationOutputName[strings.Index(nixDerivationOutputName, "-")+1:]

	imageSha512, err := getFileSha512(filepath.Join(tmpOutputDirPath, "disk.raw"))
	if err != nil {
		return err
	}

	imageMeasurementsSha512, err := getFileSha512(expectedPcrsFilePath)
	if err != nil {
		return err
	}

	manifest := domain.Manifest{
		Version:                 domain.CurrentManifestVersion,
		NixVersion:              nixVersion,
		SourceUrl:               repoUrl,
		SourceCommit:            commitHash,
		FlakeAttr:               variation,
		DrvPathHash:             nixDerivationPathHash,
		DrvOutputName:           nixDerivationOutputNameOnly,
		DrvSha512:               nixDerivationSha512,
		ImageSha512:             imageSha512,
		ImageMeasurementsSha512: imageMeasurementsSha512,
	}

	manifestBuffer := &bytes.Buffer{}
	err = manifest.Encode(manifestBuffer)
	if err != nil {
		return err
	}
	manifestBytes := manifestBuffer.Bytes()

	manifestFilePath := filepath.Join(tmpOutputDirPath, "MANIFEST")
	manifestFile, err := os.OpenFile(manifestFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	_, err = io.Copy(manifestFile, bytes.NewReader(manifestBytes))
	if err != nil {
		return err
	}

	// 4. sign manifest file and save the signature to outputDirPath/<signing-pub-key-id>.sig.asc
	log.Get().Infof("Signing manifest file with key %s...", p.keyId)
	signatureFilePath := filepath.Join(tmpOutputDirPath, fmt.Sprintf("%s.sig.asc", p.keyId))
	log.Get().Debugf("signature output path: %s", signatureFilePath)
	signCmd := exec.Command(p.gpgCmd, "--output", signatureFilePath, "--local-user", p.keyId, "--armor", "--detach-sign", manifestFilePath)
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

	digest, err := expectedPcrs.ComputeExpectedDigest(domain.HashAlgorithm(domain.ENUM_HASH_ALGORITHM_SHA256))
	if err != nil {
		return err
	}
	log.Get().Debugf("computed package digest: %s", digest)
	packageDirName := fmt.Sprintf("%s.package", digest)
	packageDirPath := filepath.Join(outputDirPath, packageDirName)
	log.Get().Infoln("Packaging files")
	err = os.MkdirAll(packageDirPath, 0755)
	if err != nil {
		return fmt.Errorf("failed to create package directory: %v", err)
	}

	filesToMove := []struct {
		src string
		dst string
	}{
		{filepath.Join(tmpOutputDirPath, "disk.raw"), filepath.Join(packageDirPath, "disk.raw")},
		{filepath.Join(tmpOutputDirPath, "expected-pcrs.json"), filepath.Join(packageDirPath, "expected-pcrs.json")},
		{filepath.Join(tmpOutputDirPath, "MANIFEST"), filepath.Join(packageDirPath, "MANIFEST")},
		{filepath.Join(tmpOutputDirPath, fmt.Sprintf("%s.sig.asc", p.keyId)), filepath.Join(packageDirPath, fmt.Sprintf("%s.sig.asc", p.keyId))},
	}

	for _, file := range filesToMove {
		srcFile, err := os.Open(file.src)
		if err != nil {
			return fmt.Errorf("failed to open source file %s: %v", file.src, err)
		}
		srcFile.Close()

		dstFile, err := os.Create(file.dst)
		if err != nil {
			return fmt.Errorf("failed to create destination file %s: %v", file.dst, err)
		}
		dstFile.Close()

		cmd := exec.Command("mv", file.src, file.dst)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to move file from %s to %s: %v", file.src, file.dst, err)
		}
	}

	log.Get().Infoln("Package created at", packageDirPath)
	return nil
}

func (p *packager) getNixVersion() (string, error) {
	nixVersionCmd := exec.Command(p.nixCmd, "--version")
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

func getFileSha512(imagePath string) (string, error) {
	diskRawFile, err := os.Open(imagePath)
	if err != nil {
		return "", err
	}
	defer diskRawFile.Close()

	hash := sha512.New()
	if _, err := io.Copy(hash, diskRawFile); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func (p *packager) listSecretKeyIDs() ([]string, error) {
	cmd := exec.Command(p.gpgCmd, "--list-secret-keys", "--with-colons")

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
