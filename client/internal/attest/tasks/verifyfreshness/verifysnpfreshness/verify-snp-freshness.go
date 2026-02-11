package verifysnpfreshness

import (
	"context"
	"encoding/hex"
	"fmt"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
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

	log.Get().Debugln("Verifying freshness of the hardware evidence by comparing the nonce with the report data")
	log.Get().Debugf("Client generated nonce: %s\n", hex.EncodeToString(input.Nonce[:]))
	log.Get().Debugf("Report data from SNP attestation report: %s\n", hex.EncodeToString(report.ReportData[:]))
	if input.Nonce != report.ReportData {
		return Output{}, fmt.Errorf("nonce mismatch, hardware evidence is not fresh")
	}
	log.Get().Debugln("Nonce matches the report data, hardware evidence is fresh")

	return Output{}, nil
}
