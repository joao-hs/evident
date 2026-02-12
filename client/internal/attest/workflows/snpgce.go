package workflows

import (
	"context"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/getgceendorsedartifacts"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/getsnpevidence"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/gettrustedcerts/getamdtrustedcerts"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/gettrustedcerts/getgcetrustedcerts"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/verifyfreshness/verifysnpfreshness"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/verifyfreshness/verifytpmfreshness"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/verifymeasurement/verifysnpmeasurement"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/verifymeasurement/verifytpmmeasurement"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/verifysignature/verifysnpsignature"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/verifysignature/verifytpmsignature"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/grpc"
)

func RunSnpGceAttestationWorkflow(ctx context.Context, client *grpc.Client, cpuCount uint8, expectedPCRs domain.ExpectedPcrDigests) error {
	var (
		err                        error
		getSnpEvidenceOutput       getsnpevidence.Output
		getamdtrustedcertsOutput   getamdtrustedcerts.Output
		getgcetrustedcertsOutput   getgcetrustedcerts.Output
		getendorsedartifactsOutput getgceendorsedartifacts.Output
	)

	log.Get().Infoln("Getting evidence")
	getSnpEvidenceOutput, err = getsnpevidence.Task(ctx, getsnpevidence.Input{
		Client: client,
	})
	if err != nil {
		return err
	}

	// Hardware evidence related sub-tasks

	log.Get().Infoln("Getting trusted certificates from AMD")
	getamdtrustedcertsOutput, err = getamdtrustedcerts.Task(ctx, getamdtrustedcerts.Input{
		Model: getSnpEvidenceOutput.Model,
	})
	if err != nil {
		return err
	}

	log.Get().Infoln("Verifying the signature of the hardware evidence")
	_, err = verifysnpsignature.Task(ctx, verifysnpsignature.Input{
		HwEvidence: getSnpEvidenceOutput.HwEvidence,
		Vcek:       getSnpEvidenceOutput.Vcek,
		Ask:        getamdtrustedcertsOutput.Ask,
		Ark:        getamdtrustedcertsOutput.Ark,
	})
	if err != nil {
		return err
	}

	log.Get().Infoln("Verifying freshness of the hardware evidence")
	_, err = verifysnpfreshness.Task(
		ctx,
		verifysnpfreshness.Input{
			SnpEvidence: getSnpEvidenceOutput.HwEvidence,
			Nonce:       getSnpEvidenceOutput.Nonce,
		},
	)
	if err != nil {
		return err
	}

	log.Get().Infoln("Getting endorsed artifacts for hardware evidence measurement verification")
	getendorsedartifactsOutput, err = getgceendorsedartifacts.Task(ctx, getgceendorsedartifacts.Input{
		CPUCount:   uint32(cpuCount),
		HwEvidence: getSnpEvidenceOutput.HwEvidence,
	})
	if err != nil {
		return err
	}

	log.Get().Infoln("Verifying measurement of the hardware evidence")
	_, err = verifysnpmeasurement.Task(
		ctx,
		verifysnpmeasurement.Input{
			SnpEvidence:     getSnpEvidenceOutput.HwEvidence,
			OvmfBinaryBytes: getendorsedartifactsOutput.OvmfBinaryBytes,
			CPUCount:        int(cpuCount),
		},
	)
	if err != nil {
		return err
	}

	// Software evidence related sub-tasks

	log.Get().Infoln("Getting trusted certificates from GCE")
	getgcetrustedcertsOutput, err = getgcetrustedcerts.Task(ctx, getgcetrustedcerts.Input{
		AttestationKeyCertificate: getSnpEvidenceOutput.Ak,
	})
	if err != nil {
		return err
	}

	log.Get().Infoln("Verifying the signature of the software evidence")
	_, err = verifytpmsignature.Task(ctx, verifytpmsignature.Input{
		SwEvidence:       getSnpEvidenceOutput.SwEvidence,
		Ak:               getSnpEvidenceOutput.Ak,
		IntermediateAkCA: getgcetrustedcertsOutput.IntermediateCACertificate,
		RootAkCA:         getgcetrustedcertsOutput.RootCACertificate,
	})

	log.Get().Infoln("Verifying freshness of the software evidence")
	_, err = verifytpmfreshness.Task(
		ctx,
		verifytpmfreshness.Input{
			TpmEvidence: getSnpEvidenceOutput.SwEvidence,
			Nonce:       getSnpEvidenceOutput.Nonce,
		},
	)
	if err != nil {
		return err
	}

	log.Get().Infoln("Verifying measurement of the software evidence")
	_, err = verifytpmmeasurement.Task(
		ctx,
		verifytpmmeasurement.Input{
			TpmEvidence:          getSnpEvidenceOutput.SwEvidence,
			ExpectedMeasurements: expectedPCRs,
		},
	)
	if err != nil {
		return err
	}

	log.Get().Infoln("SNP GCE attestation successful")
	return nil
}
