package dotevident

import "path/filepath"

/*
vm-type/
|- cloud provider/
|  |- vmId/
|  |  |- (**)
*/
/*
	(**)
	|- state/
	|  |- state.json
	|- evidence/
	|  |- hardware.raw
	|  |- software.raw
	|  |- refs/
	|  |  |- {hw-ark,hw-ask,hw-vcek,sw-ak,sw-ek}.crt
	|  |  |- {hw-digest,hw-nonce,sw-nonce,sw-pcr4,sw-pcr11}.raw
*/

type vmInfo struct {
	evidence
	vmState
}

type deployment interface{}

type deploymentImpl struct {
	store

	deploymentPath string
	contentMap     map[string]map[cloudprovider]map[string]vmInfo
}

func newDeployment(deploymentsPath string, deploymentId string) deployment {
	d := &deploymentImpl{
		store:          newStore(filepath.Join(deploymentsPath, "..")),
		deploymentPath: filepath.Join(deploymentsPath, deploymentId),
	}
	return d
}

func loadDeployment(deploymentsPath string, deploymentId string) (deployment, error) {
	d := &deploymentImpl{
		store:          newStore(filepath.Join(deploymentsPath, "..")),
		deploymentPath: filepath.Join(deploymentsPath, deploymentId),
	}
	return d, nil
}
