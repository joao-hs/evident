package dotevident

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"

	"google.golang.org/protobuf/proto"
)

const (
	// .evident/store
	_STORE_DIR string = "store"
)

type store interface {
	// fileExists returns true if the provided link exists and points to an existing store file; otherwise, returns false.
	// fileExists(linkpath string) (bool, error)
	// fileRead returns the raw content of the file pointed by the provided link
	// fileRead(linkPath string) ([]byte, error)

	// fileWrite returns true if it created a new store file (if the store file already existed, the link to it is still
	// created at the provided destination); otherwise, returns false
	Store(content []byte) (string, error)

	// StoreGrpcMessage serializes the provided gRPC message and stores it in the store, returning the path to the stored content
	StoreGrpcMessage(msg proto.Message) (string, error)
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

func (s *storeImpl) filename(content []byte) string {
	return fmt.Sprintf("%x.obj", sha256.Sum256(content))
}

func (s *storeImpl) findStoreFile(filename string) (string, error) {
	_, err := os.Stat(filepath.Join(s.storePath, filename))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return filename, nil
}

// func (s *storeImpl) findFile(linkpath string) (string, error) {
// 	// 1. linkpath should exist
// 	_, err := os.Lstat(linkpath)
// 	if err != nil {
// 		if os.IsNotExist(err) {
// 			return "", nil
// 		}
// 		return "", err
// 	}

// 	// 2. linkpath should point to an existing store file
// 	storeFileRelPath, err := os.Readlink(linkpath)
// 	if err != nil {
// 		return "", err
// 	}
// 	storeFilename := filepath.Base(storeFileRelPath)
// 	storeFilename, err = s.findStoreFile(storeFilename)
// 	if err != nil {
// 		return "", err
// 	}

// 	return storeFilename, nil
// }

// func (s *storeImpl) fileExists(linkpath string) (bool, error) {
// 	storeFilename, err := s.findFile(linkpath)
// 	if err != nil {
// 		return false, err
// 	}
// 	if storeFilename == "" {
// 		return false, nil
// 	}
// 	return true, nil
// }

// func (s *storeImpl) fileRead(linkPath string) ([]byte, error) {
// 	storeFilename, err := s.findFile(linkPath)
// 	if err != nil {
// 		return nil, err
// 	}
// 	if storeFilename == "" {
// 		return nil, fmt.Errorf("link or store file does not exist %s", linkPath)
// 	}

// 	return os.ReadFile(filepath.Join(s.storePath, storeFilename))
// }

func (s *storeImpl) Store(content []byte) (string, error) {
	storeFilename := s.filename(content)
	fullPath := filepath.Join(s.storePath, storeFilename)

	existingStoreFilename, err := s.findStoreFile(storeFilename)
	if err != nil {
		return "", err
	}
	if existingStoreFilename == "" {
		err = os.WriteFile(filepath.Join(s.storePath, storeFilename), content, 0444)
		if err != nil {
			return "", err
		}
	}

	return fullPath, nil
}

func (s *storeImpl) StoreGrpcMessage(msg proto.Message) (string, error) {
	serializedMsg, err := proto.Marshal(msg)
	if err != nil {
		return "", err
	}
	return s.Store(serializedMsg)
}
