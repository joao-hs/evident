package verifytpmmeasurement

import (
	"context"
	"encoding/hex"
	"fmt"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/packager"
)

type Input struct {
	TpmEvidence             domain.SoftwareEvidence
	OptExpectedMeasurements *domain.ExpectedPcrDigests
	OptPackages             packager.Packages
}

type Output struct{}

func Task(ctx context.Context, input Input) (Output, error) {
	var (
		err error
	)

	if (input.OptExpectedMeasurements == nil && input.OptPackages == nil) || (input.OptExpectedMeasurements != nil && input.OptPackages != nil) {
		return Output{}, fmt.Errorf("invalid task input: either expected measurements or trusted packages must be provided, but not both")
	}

	report := input.TpmEvidence.Report()
	if report == nil {
		return Output{}, fmt.Errorf("TPM report is nil")
	}

	expectedMeasurementsPtr := input.OptExpectedMeasurements
	if input.OptExpectedMeasurements == nil {
		finalPCRDigest := hex.EncodeToString(report.PcrDigest)
		log.Get().Debugf("Looking for a trusted package matching the final PCR digest %s\n", finalPCRDigest)
		pkg, err := input.OptPackages.GetPackageByFinalPcrDigest(finalPCRDigest)
		if err != nil {
			return Output{}, fmt.Errorf("failed to find a trusted package matching the final PCR digest %s: %w", finalPCRDigest, err)
		}
		log.Get().Debugf("Found a trusted package matching the final PCR digest %s\n", finalPCRDigest)

		expectedMeasurementsPtr, err = pkg.GetExpectedPcrs()
		if err != nil {
			return Output{}, fmt.Errorf("failed to get expected PCR digests from the trusted package matching the final PCR digest %s: %w", finalPCRDigest, err)
		}
		if expectedMeasurementsPtr == nil {
			return Output{}, fmt.Errorf("trusted package matching the final PCR digest %s has nil expected PCR digests", finalPCRDigest)
		}
		log.Get().Debugf("Expected PCR digests from the trusted package matching the final PCR digest %s: %+v\n", finalPCRDigest, expectedMeasurementsPtr)
	}

	log.Get().Debugln("Verifying the measurement from the TPM report matches the given expected measurements")
	log.Get().Debugln("Deriving the PCR measurement digest from the given expected measurements")
	// the quote's PcrDigest is the SHA256 hash of the concatenated PCR values
	expectedPcrDigest, err := expectedMeasurementsPtr.ComputeExpectedDigest(domain.HashAlgorithm(domain.ENUM_HASH_ALGORITHM_SHA256))
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
