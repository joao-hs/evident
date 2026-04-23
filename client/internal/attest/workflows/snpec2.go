package workflows

import (
	"context"
	"crypto"
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
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/report"
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
	reportInput *report.ReportInput,
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
		reportInput.Q1 = report.CheckResult{
			Status: report.StatusFail,
			Tag:    "Unknown",
			Detail: "Unknown",
		}
		reportInput.Q2 = report.CheckResult{
			Status: report.StatusFail,
			Tag:    "Invalid",
			Detail: report.Q2AdditionalArtifactsSignatureInvalid(),
		}
		reportInput.Q3 = report.CheckResult{
			Status: report.StatusFail,
			Tag:    "Invalid",
			Detail: report.Q3AdditionalArtifactsContentsInvalid(),
		}
		reportInput.Q4 = report.CheckResult{
			Status: report.StatusFail,
			Tag:    "Unknown",
			Detail: "Unknown",
		}
		reportInput.Q5 = report.CheckResult{
			Status: report.StatusFail,
			Tag:    "Invalid",
			Detail: report.Q5EvidenceBundleSignatureInvalid(),
		}
		reportInput.Q6 = report.CheckResult{
			Status: report.StatusFail,
			Tag:    "Missing",
			Detail: report.Q6HardwareEvidenceMissingOrInvalidFormat(),
		}
		reportInput.Q7 = report.CheckResult{
			Status: report.StatusFail,
			Tag:    "Missing",
			Detail: report.Q7SoftwareEvidenceMissingOrInvalidFormat(),
		}
		reportInput.Q10 = report.CheckResult{
			Status: report.StatusInfo,
			Tag:    domain.AMDSEVSNPModel(domain.ENUM_AMD_SEV_SNP_MODEL_UNKNOWN).String(),
			Detail: "",
		}
		return err
	} else {
		reportInput.Q1 = report.CheckResult{
			Status: report.StatusPass,
			Tag:    "Fetched",
			Detail: report.Q1AdditionalArtifactsRetrieved(optAdditionalArtifactsBundle == nil),
		}
		reportInput.Q2 = report.CheckResult{
			Status: report.StatusPass,
			Tag:    "Valid",
			Detail: report.Q2AdditionalArtifactsSignatureValid(getEc2SnpEvidenceOutput.InstanceKeyCert),
		}
		reportInput.Q3 = report.CheckResult{
			Status: report.StatusPass,
			Tag:    "Valid",
			Detail: report.Q3AdditionalArtifactsContentsValid(),
		}
		reportInput.Q4 = report.CheckResult{
			Status: report.StatusPass,
			Tag:    "Fetched",
			Detail: report.Q4EvidenceBundleRetrieved(),
		}
		reportInput.Q5 = report.CheckResult{
			Status: report.StatusPass,
			Tag:    "Valid",
			Detail: report.Q5EvidenceBundleSignatureValid(getEc2SnpEvidenceOutput.InstanceKeyCert),
		}
		reportInput.Q6 = report.CheckResult{
			Status: report.StatusPass,
			Tag:    "Present",
			Detail: report.Q6HardwareEvidencePresentValidFormat(),
		}
		reportInput.Q7 = report.CheckResult{
			Status: report.StatusPass,
			Tag:    "Present",
			Detail: report.Q7SoftwareEvidencePresentValidFormat(),
		}
		reportInput.Q10 = report.CheckResult{
			Status: report.StatusInfo,
			Tag:    report.Q10ProcessorModel(getEc2SnpEvidenceOutput.Model.String()),
			Detail: "",
		}
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
		reportInput.Q8 = report.CheckResult{
			Status: report.StatusFail,
			Tag:    "Invalid",
			Detail: report.Q8HardwareEvidenceSignatureInvalid(),
		}
		reportInput.Q11 = report.CheckResult{
			Status: report.StatusFail,
			Tag:    "Unendorsed",
			Detail: report.Q11HardwareEvidenceChainInvalid(),
		}
		return err
	} else {
		reportInput.Q8 = report.CheckResult{
			Status: report.StatusPass,
			Tag:    "Valid",
			Detail: report.Q8HardwareEvidenceSignedBy(getEc2SnpEvidenceOutput.Vlek),
		}
		reportInput.Q11 = report.CheckResult{
			Status: report.StatusPass,
			Tag:    "Endorsed",
			Detail: report.Q11HardwareEvidenceChainValid(
				"VLEK",
				getEc2SnpEvidenceOutput.Vlek,
				"ASVK",
				getamdtrustedcertsOutput.Asvk,
				getamdtrustedcertsOutput.Ark,
			),
		}
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
		reportInput.Q12 = report.CheckResult{
			Status: report.StatusFail,
			Tag:    "Stale",
			Detail: report.Q12HardwareEvidenceNotFresh(),
		}
		reportInput.Q17 = report.CheckResult{
			Status: report.StatusFail,
			Tag:    "Unbound",
			Detail: report.Q17InstanceKeyNotBoundToHardwareEvidence(),
		}
		return err
	} else {
		reportInput.Q12 = report.CheckResult{
			Status: report.StatusPass,
			Tag:    "Fresh",
			Detail: report.Q12HardwareEvidenceFresh(),
		}
		reportInput.Q17 = report.CheckResult{
			Status: report.StatusPass,
			Tag:    "Bound",
			Detail: report.Q17InstanceKeyBoundToHardwareEvidence(getEc2SnpEvidenceOutput.InstanceKeyCert),
		}
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
		reportInput.Q15 = report.CheckResult{
			Status: report.StatusSkip,
			Tag:    "Mismatch",
			Detail: report.Q15AwsKnownIssue(),
		}
	} else {
		reportInput.Q15 = report.CheckResult{
			Status: report.StatusPass,
			Tag:    "Match",
			Detail: report.Q15AwsHardwareMeasurementsMatch(),
		}
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
		reportInput.Q9 = report.CheckResult{
			Status: report.StatusFail,
			Tag:    "Invalid",
			Detail: report.Q9SoftwareEvidenceSignatureInvalid(),
		}
		if optInstanceID != nil {
			reportInput.Q13 = report.CheckResult{
				Status: report.StatusFail,
				Tag:    "Unendorsed",
				Detail: report.Q13SoftwareEvidenceChainInvalid(),
			}
		}
		return err
	} else {
		var akKey crypto.PublicKey
		if getEc2SnpEvidenceOutput.AkEc != nil {
			akKey = getEc2SnpEvidenceOutput.AkEc
		} else if getEc2SnpEvidenceOutput.AkRsa != nil {
			akKey = getEc2SnpEvidenceOutput.AkRsa
		}
		var ekKey crypto.PublicKey
		if getEc2SnpEvidenceOutput.EkEc != nil {
			ekKey = getEc2SnpEvidenceOutput.EkEc
		} else if getEc2SnpEvidenceOutput.EkRsa != nil {
			ekKey = getEc2SnpEvidenceOutput.EkRsa
		}

		reportInput.Q9 = report.CheckResult{
			Status: report.StatusPass,
			Tag:    "Valid",
			Detail: report.Q9SoftwareEvidenceSignedBy(akKey),
		}
		if optInstanceID != nil {
			reportInput.Q13 = report.CheckResult{
				Status: report.StatusPass,
				Tag:    "Endorsed",
				Detail: report.Q13AwsSoftwareEvidenceChainValid(
					akKey,
					ekKey,
				),
			}
		} else {
			reportInput.Q13 = report.CheckResult{
				Status: report.StatusSkip,
				Tag:    "Skipped",
				Detail: report.Q13AwsDoesNotEndorseWithoutInstanceID(),
			}
		}
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
		reportInput.Q14 = report.CheckResult{
			Status: report.StatusFail,
			Tag:    "Stale",
			Detail: report.Q14SoftwareEvidenceNotFresh(),
		}
		reportInput.Q18 = report.CheckResult{
			Status: report.StatusFail,
			Tag:    "Unbound",
			Detail: report.Q18InstanceKeyNotBoundToSoftwareEvidence(),
		}
		return err
	} else {
		reportInput.Q14 = report.CheckResult{
			Status: report.StatusPass,
			Tag:    "Fresh",
			Detail: report.Q14SoftwareEvidenceFresh(),
		}
		reportInput.Q18 = report.CheckResult{
			Status: report.StatusPass,
			Tag:    "Bound",
			Detail: report.Q18InstanceKeyBoundToSoftwareEvidence(getEc2SnpEvidenceOutput.InstanceKeyCert),
		}
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
		reportInput.Q16 = report.CheckResult{
			Status: report.StatusFail,
			Tag:    "Mismatch",
			Detail: report.Q16SoftwareMeasurementsMismatch(),
		}
		return err
	} else {
		reportInput.Q16 = report.CheckResult{
			Status: report.StatusPass,
			Tag:    "Match",
			Detail: report.Q16SoftwareMeasurementsMatch(),
		}
	}

	return nil
}
