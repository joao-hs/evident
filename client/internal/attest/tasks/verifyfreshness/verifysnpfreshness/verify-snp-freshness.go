package verifysnpfreshness

import (
	"context"
	"fmt"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
)

type Input struct {
	SnpEvidence domain.HardwareEvidence[*domain.AmdSevSnpAttestationReport]
	Nonce       [64]byte
}

type Output struct{}

func Task(ctx context.Context, input Input) (Output, error) {
	report := input.SnpEvidence.Report()
	if report == nil {
		return Output{}, fmt.Errorf("SNP attestation report is nil")
	}

	if input.Nonce != report.ReportData {
		return Output{}, fmt.Errorf("nonce mismatch, hardware evidence is not fresh")
	}

	return Output{}, nil
}
