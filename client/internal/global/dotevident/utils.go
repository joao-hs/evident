package dotevident

import (
	"errors"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"path"
	"path/filepath"
)

const (
	_POLICY_DIR string = "attestation-policy"
)

// healthCheck checks if the application is able to create and delete files in
// the directory. If not, it returns the corresponding error; otherwise
// nil. Further interactions with the directory will assume filesystem errors as
// impossible, and panic if they exist.
func healthCheck(path string) error {
	err := os.MkdirAll(path, 0775)
	if err != nil {
		return fmt.Errorf("failed to create directory %s: %w", path, err)
	}

	testFilePath := filepath.Join(path, fmt.Sprintf(".delete_%d", rand.Int()))

	testFile, err := os.Create(testFilePath)
	if err != nil {
		return fmt.Errorf("failed to create a test file in store: %w", err)
	}
	err = testFile.Close()
	if err != nil {
		return fmt.Errorf("failed to close test file in store: %w", err)
	}

	err = os.Remove(testFilePath)
	if err != nil {
		return fmt.Errorf("failed to remove test file in store: %w", err)
	}

	return nil
}

func subdirectoryExists(rootPath string, subdirectoryName string) (bool, error) {
	_, err := os.Stat(path.Join(rootPath, subdirectoryName))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func directoryStructureExists(rootTargetPath string) (bool, error) {
	var (
		ok  bool
		err error
	)

	if ok, err = subdirectoryExists(rootTargetPath, ""); err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}

	if ok, err = subdirectoryExists(rootTargetPath, _DEPLOYMENTS_DIR); err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}

	if ok, err = subdirectoryExists(rootTargetPath, _STORE_DIR); err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}

	return true, nil
}
