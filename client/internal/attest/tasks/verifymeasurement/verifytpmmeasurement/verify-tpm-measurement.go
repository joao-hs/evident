package verifytpmmeasurement

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
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

	// the quote's PcrDigest is the SHA256 hash of the concatenated PCR values
	concatExpectedMeasurements := strings.Join(input.ExpectedMeasurements.AsSlice(), "")
	concatExpectedMeasurementsBytes, err := hex.DecodeString(concatExpectedMeasurements)
	if err != nil {
		return Output{}, fmt.Errorf("failed to decode expected measurements: %w", err)
	}
	expectedPcrDigest := sha256.Sum256(concatExpectedMeasurementsBytes)

	if !slices.Equal(report.PcrDigest, expectedPcrDigest[:]) {
		return Output{}, fmt.Errorf("TPM measurement verification failed: expected PCR digest %s, got %s",
			hex.EncodeToString(expectedPcrDigest[:]), hex.EncodeToString(report.PcrDigest))
	}

	return Output{}, nil
}
