package dotevident

import (
	"path/filepath"
)

/*
- evidence: all auditable evidence goes in here
	- idea: generate a audit.sh script with bash commands that will automate evidence audit verification
	- AMD SNP's attestation report (hardware)
	- vTPM's quote (software)
	- trusted-references:
		- .raw images (?)
		- nonces
		- expected software measurements
		- expected hardware measurements
*/

const (
	// .../[vm-id]-info/evidence
	_EVIDENCE_DIR string = "evidence"
	// .../[vm-id]-info/evidence/refs
	_EVIDENCE_REFS_DIR string = "refs"
)

type evidence interface {
}

type evidenceImpl struct {
	store

	evidencePath           string
	referenceArtifactsPath string
}

func newEvidence(vmInfoPath string) evidence {
	// .evident/deployments/[deployment]/[vm-type]/[csp]/[vm-id]-info/
	dotEvidentPath := filepath.Join(vmInfoPath, "../../../..")
	evidencePath := filepath.Join(vmInfoPath, _EVIDENCE_DIR)
	return &evidenceImpl{
		store:                  newStore(dotEvidentPath),
		evidencePath:           evidencePath,
		referenceArtifactsPath: filepath.Join(evidencePath, _EVIDENCE_REFS_DIR),
	}
}

func loadEvidence(vmInfoPath string) (evidence, error) {
	// .evident/deployments/[deployment]/[vm-type]/[csp]/[vm-id]-info/
	dotEvidentPath := filepath.Join(vmInfoPath, "../../../..")
	evidencePath := filepath.Join(vmInfoPath, _EVIDENCE_DIR)
	return &evidenceImpl{
		store:                  newStore(dotEvidentPath),
		evidencePath:           evidencePath,
		referenceArtifactsPath: filepath.Join(evidencePath, _EVIDENCE_REFS_DIR),
	}, nil
}
