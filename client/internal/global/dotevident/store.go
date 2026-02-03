package dotevident

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
)

const (
	// .evident/store
	_STORE_DIR string = "store"
)

type store interface {
	// fileExists returns true if the provided link exists and points to an existing store file; otherwise, returns false.
	fileExists(linkpath string) (bool, error)
	// fileRead returns the raw content of the file pointed by the provided link
	fileRead(linkPath string) ([]byte, error)
	// fileWrite returns true if it created a new store file (if the store file already existed, the link to it is still
	// created at the provided destination); otherwise, returns false
	fileWrite(content []byte, linkPath string) (bool, error)
}

type storeImpl struct {
	storePath string
}

func newStore(dotEvidentPath string) store {
	s := &storeImpl{
		storePath: filepath.Join(dotEvidentPath, _STORE_DIR),
	}
	err := healthCheck(s.storePath)
	if err != nil {
		panic(err)
	}
	return s
}

func loadStore(dotEvidentPath string) (store, error) {
	s := &storeImpl{
		storePath: filepath.Join(dotEvidentPath, _STORE_DIR),
	}
	err := healthCheck(s.storePath)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (self *storeImpl) filename(content []byte) string {
	return fmt.Sprintf("%x.obj", sha256.Sum256(content))
}

func (self *storeImpl) findStoreFile(filename string) (string, error) {
	_, err := os.Stat(filepath.Join(self.storePath, filename))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return filename, nil
}

func (self *storeImpl) findFile(linkpath string) (string, error) {
	// 1. linkpath should exist
	_, err := os.Lstat(linkpath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}

	// 2. linkpath should point to an existing store file
	storeFileRelPath, err := os.Readlink(linkpath)
	if err != nil {
		return "", err
	}
	storeFilename := filepath.Base(storeFileRelPath)
	storeFilename, err = self.findStoreFile(storeFilename)
	if err != nil {
		return "", err
	}

	return storeFilename, nil
}

func (self *storeImpl) fileExists(linkpath string) (bool, error) {
	storeFilename, err := self.findFile(linkpath)
	if err != nil {
		return false, err
	}
	if storeFilename == "" {
		return false, nil
	}
	return true, nil
}

func (self *storeImpl) fileRead(linkPath string) ([]byte, error) {
	storeFilename, err := self.findFile(linkPath)
	if err != nil {
		return nil, err
	}
	if storeFilename == "" {
		return nil, fmt.Errorf("link or store file does not exist %s", linkPath)
	}

	return os.ReadFile(filepath.Join(self.storePath, storeFilename))
}

func (self *storeImpl) fileWrite(content []byte, linkPath string) (bool, error) {
	isNewFile := false

	storeFilename := self.filename(content)

	existingStoreFilename, err := self.findStoreFile(storeFilename)
	if err != nil {
		return false, err
	}
	if existingStoreFilename == "" {
		isNewFile = true
		err = os.WriteFile(filepath.Join(self.storePath, storeFilename), content, 0444)
		if err != nil {
			return false, err
		}
	}

	err = os.Link(filepath.Join(self.storePath, existingStoreFilename), linkPath)
	if err != nil {
		return false, err
	}

	return isNewFile, nil
}
