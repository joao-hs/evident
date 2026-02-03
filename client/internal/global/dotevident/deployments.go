package dotevident

import (
	"os"
	"path/filepath"
)

const (
	// .evident/deployments
	_DEPLOYMENTS_DIR string = "deployments"
)

type deployments interface {
}

type deploymentsImpl struct {
	store

	deploymentsPath string
	deployments     []deployment
}

func newDeployments(dotEvidentPath string) deployments {
	ds := &deploymentsImpl{
		store:           newStore(dotEvidentPath),
		deploymentsPath: filepath.Join(dotEvidentPath, _DEPLOYMENTS_DIR),
	}
	err := healthCheck(ds.deploymentsPath)
	if err != nil {
		panic(err)
	}
	return ds
}

func loadDeployments(dotEvidentPath string) (deployments, error) {
	ds := &deploymentsImpl{
		store:           newStore(dotEvidentPath),
		deploymentsPath: filepath.Join(dotEvidentPath, _DEPLOYMENTS_DIR),
		deployments:     make([]deployment, 0),
	}

	err := healthCheck(ds.deploymentsPath)
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(ds.deploymentsPath)
	if err != nil {
		return nil, err
	}

	for _, dirEntry := range entries {
		if !dirEntry.IsDir() {
			continue
		}
		d, err := loadDeployment(ds.deploymentsPath, dirEntry.Name())
		if err != nil {
			// TODO: warn, don't break
			continue
		}
		ds.deployments = append(ds.deployments, d)
	}

	return ds, nil
}
