package env

import (
	"os"
	"path"
	"sync"
)

const (
	DEFAULT_DOTEVIDENT_ROOT_PATH = ".evident"
	DOTEVIDENT_PATH_VARNAME      = "DOTEVIDENT"
)

var (
	once      sync.Once
	singleton Env
)

type Env interface {
	GetDotEvidentPath() string
}

func Get() Env {
	once.Do(func() {
		singleton = newEnv()
	})
	return singleton
}

type envImpl struct {
	dotEvidentPath string
}

func newEnv() Env {
	dotEvidentPath, ok := os.LookupEnv(DOTEVIDENT_PATH_VARNAME)
	if !ok {
		dotEvidentPath = DEFAULT_DOTEVIDENT_ROOT_PATH
	}
	dotEvidentPath = path.Clean(dotEvidentPath)

	return &envImpl{
		dotEvidentPath: dotEvidentPath,
	}
}

func (self *envImpl) GetDotEvidentPath() string {
	return self.dotEvidentPath
}
