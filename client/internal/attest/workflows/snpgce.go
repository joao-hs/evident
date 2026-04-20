package workflows

import (
	"context"
	"fmt"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/getgceendorsedartifacts"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/getsnpevidence/getgcesnpevidence"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/gettrustedcerts/getamdtrustedcerts"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/gettrustedcerts/getgcetrustedcerts"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/verifyfreshness/verifysnpfreshness"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/verifyfreshness/verifytpmfreshness"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/verifymeasurement/verifysnpmeasurement"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/verifymeasurement/verifytpmmeasurement"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/verifysignature/verifysnpsignature"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/verifysignature/verifytpmsignature/verifygcetpmsignature"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/grpc"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/packager"
	pb "gitlab.com/dpss-inesc-id/achilles-cvm/client/pb/evident_protocol/v1"
)

func RunSnpGceAttestationWorkflow(
	ctx context.Context,
	client *grpc.AttesterServiceClient,
	optCpuCount *uint8,
	optExpectedPCRs *domain.ExpectedPcrDigests,
	optPkgs packager.Packages,
	optAdditionalArtifactsBundle *pb.AdditionalArtifactsBundle,
) error {
	var (
		err                        error
		getGceSnpEvidenceOutput    getgcesnpevidence.Output
		getamdtrustedcertsOutput   getamdtrustedcerts.Output
		getgcetrustedcertsOutput   getgcetrustedcerts.Output
		getendorsedartifactsOutput getgceendorsedartifacts.Output
	)

	if (optExpectedPCRs == nil && optPkgs == nil) || (optExpectedPCRs != nil && optPkgs != nil) {
		return fmt.Errorf("invalid workflow options: either expected PCR digests or trusted packages must be provided, but not both")
	}

	log.Get().Infoln("Getting evidence")
	getGceSnpEvidenceOutput, err = getgcesnpevidence.Task(ctx, getgcesnpevidence.Input{
		Client:                       client,
		OptAdditionalArtifactsBundle: optAdditionalArtifactsBundle,
	})
	if err != nil {
		return err
	}

	// Hardware evidence related sub-tasks

	log.Get().Infoln("Getting trusted certificates from AMD")
	getamdtrustedcertsOutput, err = getamdtrustedcerts.Task(ctx, getamdtrustedcerts.Input{
		Model: getGceSnpEvidenceOutput.Model,
	})
	if err != nil {
		return err
	}

	log.Get().Infoln("Getting trusted certificates from GCE")
	getgcetrustedcertsOutput, err = getgcetrustedcerts.Task(ctx, getgcetrustedcerts.Input{
		Ak: getGceSnpEvidenceOutput.AkCert,
	})
	if err != nil {
		return err
	}

	log.Get().Infoln("Verifying the signature of the hardware evidence")
	_, err = verifysnpsignature.Task(ctx, verifysnpsignature.Input{
		HwEvidence: getGceSnpEvidenceOutput.HwEvidence,
		Vcek:       getGceSnpEvidenceOutput.Vcek,
		Ask:        getamdtrustedcertsOutput.Ask,
		Ark:        getamdtrustedcertsOutput.Ark,
	})
	if err != nil {
		return err
	}

	log.Get().Infoln("Verifying freshness of the hardware evidence")
	// Also verifies bindings.
	// UserData := SHA512(nonce || instanceKey || akCert)
	_, err = verifysnpfreshness.Task(
		ctx,
		verifysnpfreshness.Input{
			SnpEvidence:  getGceSnpEvidenceOutput.HwEvidence,
			Nonce:        getGceSnpEvidenceOutput.Nonce,
			InstanceCert: getGceSnpEvidenceOutput.InstanceKeyCert,
			AkCert:       getgcetrustedcertsOutput.Ak,
			AkEc:         nil, // AK is indentified by its certificate
			AkRsa:        nil, // AK is indentified by its certificate
			Secret:       nil, // No secret is needed; AK certificate proves AK presence in the TPM
		},
	)
	if err != nil {
		return err
	}

	log.Get().Infoln("Getting endorsed artifacts for hardware evidence measurement verification")
	getendorsedartifactsOutput, err = getgceendorsedartifacts.Task(ctx, getgceendorsedartifacts.Input{
		CPUCount:   optCpuCount,
		HwEvidence: getGceSnpEvidenceOutput.HwEvidence,
	})
	if err != nil {
		return err
	}

	log.Get().Infoln("Verifying measurement of the hardware evidence")
	_, err = verifysnpmeasurement.Task(
		ctx,
		verifysnpmeasurement.Input{
			SnpEvidence:          getGceSnpEvidenceOutput.HwEvidence,
			OvmfBinaryBytes:      getendorsedartifactsOutput.OvmfBinaryBytes,
			CPUCount:             int(getendorsedartifactsOutput.CPUCount),
			CloudServiceProvider: domain.CloudServiceProvider(domain.ENUM_CLOUD_SERVICE_PROVIDER_GCP),
		},
	)
	if err != nil {
		return err
	}

	log.Get().Infoln("Verifying the signature of the software evidence")
	_, err = verifygcetpmsignature.Task(ctx, verifygcetpmsignature.Input{
		SwEvidence:           getGceSnpEvidenceOutput.SwEvidence,
		AkCert:               getgcetrustedcertsOutput.Ak,
		IntermediateAkCACert: getgcetrustedcertsOutput.IntermediateCACertificate,
		RootAkCACert:         getgcetrustedcertsOutput.RootCACertificate,
	})
	if err != nil {
		return err
	}

	log.Get().Infoln("Verifying freshness of the software evidence")
	// Also verifies bindings.
	_, err = verifytpmfreshness.Task(
		ctx,
		verifytpmfreshness.Input{
			TpmEvidence:  getGceSnpEvidenceOutput.SwEvidence,
			Nonce:        getGceSnpEvidenceOutput.Nonce,
			InstanceCert: getGceSnpEvidenceOutput.InstanceKeyCert,
		},
	)
	if err != nil {
		return err
	}

	log.Get().Infoln("Verifying measurement of the software evidence")
	_, err = verifytpmmeasurement.Task(
		ctx,
		verifytpmmeasurement.Input{
			TpmEvidence:             getGceSnpEvidenceOutput.SwEvidence,
			OptExpectedMeasurements: optExpectedPCRs,
			OptPackages:             optPkgs,
		},
	)
	if err != nil {
		return err
	}

	log.Get().Infoln("SNP GCE attestation successful")
	return nil
}
