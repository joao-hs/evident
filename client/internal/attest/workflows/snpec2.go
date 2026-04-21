package workflows

import (
	"context"
	"fmt"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/getec2endorsedartifacts"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/getsnpevidence/getec2snpevidence"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/gettrustedcerts/getamdtrustedcerts"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/verifyfreshness/verifysnpfreshness"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/verifyfreshness/verifytpmfreshness"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/verifymeasurement/verifysnpmeasurement"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/verifymeasurement/verifytpmmeasurement"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/verifysignature/verifysnpsignature"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/verifysignature/verifytpmsignature/verifyec2tpmsignature"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/grpc"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/packager"
	pb "gitlab.com/dpss-inesc-id/achilles-cvm/client/pb/evident_protocol/v1"
)

func RunSnpEc2AttestationWorkflow(
	ctx context.Context,
	client *grpc.AttesterServiceClient,
	optCpuCount *uint8,
	optInstanceID *string,
	optExpectedPCRs *domain.ExpectedPcrDigests,
	optPkgs packager.Packages,
	optAdditionalArtifactsBundle *pb.AdditionalArtifactsBundle,
) error {
	var (
		err                        error
		getEc2SnpEvidenceOutput    getec2snpevidence.Output
		getamdtrustedcertsOutput   getamdtrustedcerts.Output
		getendorsedartifactsOutput getec2endorsedartifacts.Output
	)

	if (optExpectedPCRs == nil && optPkgs == nil) || (optExpectedPCRs != nil && optPkgs != nil) {
		return fmt.Errorf("invalid workflow options: either expected PCR digests or trusted packages must be provided, but not both")
	}

	log.Get().Infoln("Getting evidence")
	getEc2SnpEvidenceOutput, err = getec2snpevidence.Task(ctx, getec2snpevidence.Input{
		Client:                       client,
		OptAdditionalArtifactsBundle: optAdditionalArtifactsBundle,
	})
	if err != nil {
		return err
	}

	// Hardware evidence related sub-tasks

	log.Get().Infoln("Getting trusted certificates from AMD")
	getamdtrustedcertsOutput, err = getamdtrustedcerts.Task(ctx, getamdtrustedcerts.Input{
		Model: getEc2SnpEvidenceOutput.Model,
	})
	if err != nil {
		return err
	}

	log.Get().Infoln("Verifying the signature of the hardware evidence")
	_, err = verifysnpsignature.Task(ctx, verifysnpsignature.Input{
		HwEvidence: getEc2SnpEvidenceOutput.HwEvidence,
		Vlek:       getEc2SnpEvidenceOutput.Vlek,
		Asvk:       getamdtrustedcertsOutput.Asvk,
		Ark:        getamdtrustedcertsOutput.Ark,
	})
	if err != nil {
		return err
	}

	log.Get().Infoln("Verifying freshness of the hardware evidence")
	// Also verifies bindings
	_, err = verifysnpfreshness.Task(ctx, verifysnpfreshness.Input{
		SnpEvidence:  getEc2SnpEvidenceOutput.HwEvidence,
		Nonce:        getEc2SnpEvidenceOutput.Nonce,
		InstanceCert: getEc2SnpEvidenceOutput.InstanceKeyCert,
		AkCert:       nil, // No certificate for AK in EC2, Secret will prove EK-AK co-presence in the TPM
		AkEc:         getEc2SnpEvidenceOutput.AkEc,
		AkRsa:        getEc2SnpEvidenceOutput.AkRsa,
		Secret:       getEc2SnpEvidenceOutput.Secret[:],
	})
	if err != nil {
		return err
	}

	log.Get().Infoln("Getting endorsed artifacts for measurement verification")
	getendorsedartifactsOutput, err = getec2endorsedartifacts.Task(
		ctx,
		getec2endorsedartifacts.Input{
			OptInstanceID: optInstanceID,
		},
	)
	if err != nil {
		return err
	}

	log.Get().Infoln("Verifying measurement of the hardware evidence")
	_, err = verifysnpmeasurement.Task(
		ctx,
		verifysnpmeasurement.Input{
			SnpEvidence:          getEc2SnpEvidenceOutput.HwEvidence,
			OvmfBinaryBytes:      getendorsedartifactsOutput.UefiBinary,
			CPUCount:             int(*optCpuCount),
			CloudServiceProvider: domain.CloudServiceProvider(domain.ENUM_CLOUD_SERVICE_PROVIDER_AWS),
		},
	)
	if err != nil {
		log.Get().Warnf("Known issue: https://github.com/aws/uefi/issues/19; Measurement verification of the hardware evidence failed: %v; proceeding", err)
	}

	log.Get().Infoln("Verifying the signature of the software evidence")
	_, err = verifyec2tpmsignature.Task(ctx, verifyec2tpmsignature.Input{
		SwEvidence:    getEc2SnpEvidenceOutput.SwEvidence,
		AkEc:          getEc2SnpEvidenceOutput.AkEc,
		AkRsa:         getEc2SnpEvidenceOutput.AkRsa,
		OptInstanceID: optInstanceID,
		EkEc:          getEc2SnpEvidenceOutput.EkEc,
		ExpectedEkEc:  getendorsedartifactsOutput.EkEc,
		EkRsa:         getEc2SnpEvidenceOutput.EkRsa,
		ExpectedEkRsa: getendorsedartifactsOutput.EkRsa,
	})
	if err != nil {
		return err
	}

	log.Get().Infoln("Verifying freshness of the software evidence")
	// Also verifies bindings.
	_, err = verifytpmfreshness.Task(
		ctx,
		verifytpmfreshness.Input{
			TpmEvidence:  getEc2SnpEvidenceOutput.SwEvidence,
			Nonce:        getEc2SnpEvidenceOutput.Nonce,
			InstanceCert: getEc2SnpEvidenceOutput.InstanceKeyCert,
			Secret:       getEc2SnpEvidenceOutput.Secret[:],
		},
	)
	if err != nil {
		return err
	}

	log.Get().Infoln("Verifying measurement of the software evidence")
	_, err = verifytpmmeasurement.Task(
		ctx,
		verifytpmmeasurement.Input{
			TpmEvidence:             getEc2SnpEvidenceOutput.SwEvidence,
			OptExpectedMeasurements: optExpectedPCRs,
			OptPackages:             optPkgs,
		},
	)
	if err != nil {
		return err
	}

	log.Get().Infoln("SNP EC2 attestation successful")
	return nil
}
