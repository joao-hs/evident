package packager

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/keyring"
)

/*
 * /etc/evident/trusted-packages/
 * ├── <final-pcr-digest>.package/
 * │	├── disk.raw                  // optional, if the package was built and installed locally
 * │	├── expected-pcrs.json
 * │	├── MANIFEST
 * │	└── <KEY_ID>.sig.asc
 * └── ...                            // other packages
 */

const (
	TrustedPackagesDirPath       = "/etc/evident/trusted-packages"
	trustedPackageDirNamePattern = "^([a-fA-F0-9]{64})\\.package$" // sha256 digest in hex is 64 characters long
	ManifestFileName             = "MANIFEST"
	ExpectedPcrsFileName         = "expected-pcrs.json"
	signatureFileNamePattern     = "^[a-zA-Z0-9_-]+\\.sig\\.asc$"
)

type Package interface {
	GetExpectedPcrs() (*domain.ExpectedPcrDigests, error)
}

type pkg struct {
	expectedPcrDigests *domain.ExpectedPcrDigests
}

type Packages interface {
	GetPackageByFinalPcrDigest(sha256PcrDigest string) (Package, error)
}

type packages struct {
	pkgIndex map[string]Package
}

func LoadTrustedPackages() (Packages, error) {
	// TODO: allow other locations
	// assuming trusted packages are under /etc/evident/trusted-packages
	err := assertPackagesDir()
	if err != nil {
		return nil, err
	}

	kr, err := keyring.New()
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(TrustedPackagesDirPath)
	if err != nil {
		return nil, err
	}

	pkgIndex := make(map[string]Package)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		name := entry.Name()
		finalPcrDigest, ok := sanitizePackageDirName(name)
		if !ok {
			continue
		}
		pkgDirPath := filepath.Join(TrustedPackagesDirPath, name)

		loaded, err := loadPackage(pkgDirPath, kr)
		if err != nil {
			log.Get().Warnf("skipping package %q: %v", name, err)
			continue
		}

		pkgIndex[finalPcrDigest] = loaded
	}

	return &packages{pkgIndex: pkgIndex}, nil
}

func (p *packages) GetPackageByFinalPcrDigest(sha256PcrDigest string) (Package, error) {
	pkg, ok := p.pkgIndex[sha256PcrDigest]
	if !ok {
		return nil, fmt.Errorf("package with final PCR digest %s not found", sha256PcrDigest)
	}

	return pkg, nil
}

func (p *pkg) GetExpectedPcrs() (*domain.ExpectedPcrDigests, error) {
	if p.expectedPcrDigests == nil {
		return nil, fmt.Errorf("package does not have expected PCR digests")
	}
	return p.expectedPcrDigests, nil
}

func loadPackage(pkgDirPath string, kr keyring.TrustedImageDistributorKeyRing) (Package, error) {
	dirInfo, err := os.Stat(pkgDirPath)
	if err != nil {
		return nil, fmt.Errorf("cannot stat package directory: %w", err)
	}
	if !dirInfo.IsDir() {
		return nil, fmt.Errorf("%s exists but is not a directory", pkgDirPath)
	}

	manifestPath := filepath.Join(pkgDirPath, ManifestFileName)
	if err := assertFileExists(manifestPath); err != nil {
		return nil, err
	}

	sigPaths, err := findSigFiles(pkgDirPath)
	if err != nil {
		return nil, err
	}

	if err := verifyAnySignature(manifestPath, sigPaths, kr); err != nil {
		return nil, err
	}

	digests, err := loadExpectedPcrs(filepath.Join(pkgDirPath, ExpectedPcrsFileName))
	if err != nil {
		return nil, fmt.Errorf("cannot load %s: %w", ExpectedPcrsFileName, err)
	}

	return &pkg{expectedPcrDigests: digests}, nil
}

func assertPackagesDir() error {
	info, err := os.Stat(TrustedPackagesDirPath)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("%s exists but is not a directory", TrustedPackagesDirPath)
		}
		// TODO: check if world-readable, onwer-writable, and owned by root
		return nil
	}

	if !os.IsNotExist(err) {
		return fmt.Errorf("failed to stat trusted packages directory: %w", err)
	}

	return err
}

func assertFileExists(path string) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("required file %s is missing", filepath.Base(path))
		}
		return fmt.Errorf("cannot stat %s: %w", filepath.Base(path), err)
	}
	return nil
}

func findSigFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("cannot read package directory: %w", err)
	}

	pattern := regexp.MustCompile(signatureFileNamePattern)

	var sigs []string
	for _, e := range entries {
		if !e.IsDir() && pattern.MatchString(e.Name()) {
			sigs = append(sigs, filepath.Join(dir, e.Name()))
		}
	}

	if len(sigs) == 0 {
		return nil, fmt.Errorf("no signature files found in %s", dir)
	}

	return sigs, nil
}

func verifyAnySignature(manifestPath string, sigPaths []string, kr keyring.TrustedImageDistributorKeyRing) error {
	for _, sigPath := range sigPaths {
		result, err := kr.VerifyDetached(sigPath, manifestPath)
		if err != nil {
			log.Get().Warnf("could not verify signature %s: %v", filepath.Base(sigPath), err)
			continue
		}
		if result.IsValid() {
			if !result.IsTrusted() {
				log.Get().Warnf("signature %s is valid but untrusted", filepath.Base(sigPath))
				continue
			}
			return nil
		}
		log.Get().Warnf("signature %s is invalid", filepath.Base(sigPath))
	}

	return fmt.Errorf("no valid signature found among %d candidate(s) for %s", len(sigPaths), manifestPath)
}

func loadExpectedPcrs(path string) (*domain.ExpectedPcrDigests, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var digests domain.ExpectedPcrDigests
	if err := json.Unmarshal(data, &digests); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	return &digests, nil
}

func sanitizePackageDirName(name string) (string, bool) {
	pattern := regexp.MustCompile(trustedPackageDirNamePattern)

	matches := pattern.FindStringSubmatch(name)
	if matches == nil || len(matches) != 2 {
		return "", false
	}

	return matches[1], true
}
