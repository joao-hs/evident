package dotevident

import "path"

/*
- attestation-policy: configuration of what's allowed to failed and expected to pass
	- per cloud provider / per role
*/

type policy interface {
}

type policyImpl struct {
	store
}

func newPolicy(dotEvidentPath string) policy {
	return &policyImpl{}
}

func loadPolicy(dotEvidentPath string) (policy, error) {
	_ = path.Join(dotEvidentPath, _POLICY_DIR)
	return &policyImpl{}, nil
}
