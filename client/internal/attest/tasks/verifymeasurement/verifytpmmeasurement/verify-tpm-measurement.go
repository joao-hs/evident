package verifytpmmeasurement

import (
	"context"
	"encoding/hex"
	"fmt"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
)

type Input struct {
	TpmEvidence          domain.SoftwareEvidence
	ExpectedMeasurements domain.ExpectedPcrDigests
}

type Output struct{}

func Task(ctx context.Context, input Input) (Output, error) {
	report := input.TpmEvidence.Report()
	if report == nil {
		return Output{}, fmt.Errorf("TPM report is nil")
	}

	log.Get().Debugln("Verifying the measurement from the TPM report matches the given expected measurements")
	log.Get().Debugln("Deriving the PCR measurement digest from the given expected measurements")
	// the quote's PcrDigest is the SHA256 hash of the concatenated PCR values
	expectedPcrDigest, err := input.ExpectedMeasurements.ComputeExpectedDigest(domain.HashAlgorithm(domain.ENUM_HASH_ALGORITHM_SHA256))
	if err != nil {
		return Output{}, err
	}
	log.Get().Debugf("Expected PCR digest derived from the given expected measurements: %s\n", expectedPcrDigest)

	log.Get().Debugf("PCR digest from TPM report: %s\n", hex.EncodeToString(report.PcrDigest))
	if hex.EncodeToString(report.PcrDigest) != expectedPcrDigest {
		return Output{}, fmt.Errorf("TPM measurement verification failed: expected PCR digest %s, got %s",
			expectedPcrDigest, hex.EncodeToString(report.PcrDigest))
	}
	log.Get().Debugln("Measurement from TPM report matches the expected PCR digest derived from the given expected measurements")

	return Output{}, nil
}
