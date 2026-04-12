package dotevident

import (
	"sync"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/env"
)

var (
	once      sync.Once
	singleton DotEvident
)

func Get() DotEvident {
	once.Do(
		func() {
			singleton = loadOrNewDotEvident()
		},
	)
	return singleton
}

type DotEvident interface {
	store
	logs
}

type dotEvident struct {
	// evidence
	// policy
	store
	logs
}

func loadOrNewDotEvident() DotEvident {
	ok, err := directoryStructureExists(env.Get().GetDotEvidentPath())
	if err != nil {
		panic(err)
	}

	if !ok {
		return newDotEvident()
	}

	impl, err := loadDotEvident()
	if err != nil {
		panic(err)
	}
	return impl
}

func newDotEvident() DotEvident {
	dotEvidentPath := env.Get().GetDotEvidentPath()
	return &dotEvident{
		store: newStore(dotEvidentPath),
		logs:  newLogs(dotEvidentPath),
	}
}

func loadDotEvident() (DotEvident, error) {
	dotEvidentPath := env.Get().GetDotEvidentPath()

	loadedStore, err := loadStore(dotEvidentPath)
	if err != nil {
		return nil, err
	}

	logs := newLogs(dotEvidentPath)

	return &dotEvident{
		store: loadedStore,
		logs:  logs,
	}, nil
}
