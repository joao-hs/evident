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
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/report"
	pb "gitlab.com/dpss-inesc-id/achilles-cvm/client/pb/evident_protocol/v1"
)

func RunSnpGceAttestationWorkflow(
	ctx context.Context,
	client *grpc.AttesterServiceClient,
	optCpuCount *uint8,
	optExpectedPCRs *domain.ExpectedPcrDigests,
	optPkgs packager.Packages,
	optAdditionalArtifactsBundle *pb.AdditionalArtifactsBundle,
	reportInput *report.ReportInput,
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
			Detail: report.Q2AdditionalArtifactsSignatureValid(getGceSnpEvidenceOutput.InstanceKeyCert),
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
			Detail: report.Q5EvidenceBundleSignatureValid(getGceSnpEvidenceOutput.InstanceKeyCert),
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
			Tag:    report.Q10ProcessorModel(getGceSnpEvidenceOutput.Model.String()),
			Detail: "",
		}
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
			Detail: report.Q8HardwareEvidenceSignedBy(getGceSnpEvidenceOutput.Vcek),
		}
		reportInput.Q11 = report.CheckResult{
			Status: report.StatusPass,
			Tag:    "Endorsed",
			Detail: report.Q11HardwareEvidenceChainValid(
				"VCEK",
				getGceSnpEvidenceOutput.Vcek,
				"ASK",
				getamdtrustedcertsOutput.Asvk,
				getamdtrustedcertsOutput.Ark,
			),
		}
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
			Detail: report.Q17InstanceKeyBoundToHardwareEvidence(getGceSnpEvidenceOutput.InstanceKeyCert),
		}
	}

	log.Get().Infoln("Getting endorsed artifacts for hardware evidence measurement verification")
	getendorsedartifactsOutput, err = getgceendorsedartifacts.Task(ctx, getgceendorsedartifacts.Input{
		CPUCount:   optCpuCount,
		HwEvidence: getGceSnpEvidenceOutput.HwEvidence,
	})
	if err != nil {
		reportInput.Q15 = report.CheckResult{
			Status: report.StatusFail,
			Tag:    "Mismatch",
			Detail: report.Q15HardwareMeasurementsMismatch(),
		}
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
		reportInput.Q15 = report.CheckResult{
			Status: report.StatusFail,
			Tag:    "Mismatch",
			Detail: report.Q15HardwareMeasurementsMismatch(),
		}
		return err
	} else {
		reportInput.Q15 = report.CheckResult{
			Status: report.StatusPass,
			Tag:    "Match",
			Detail: report.Q15GcpHardwareMeasurementsMatch(),
		}
	}

	log.Get().Infoln("Verifying the signature of the software evidence")
	_, err = verifygcetpmsignature.Task(ctx, verifygcetpmsignature.Input{
		SwEvidence:           getGceSnpEvidenceOutput.SwEvidence,
		AkCert:               getgcetrustedcertsOutput.Ak,
		IntermediateAkCACert: getgcetrustedcertsOutput.IntermediateCACertificate,
		RootAkCACert:         getgcetrustedcertsOutput.RootCACertificate,
	})
	if err != nil {
		reportInput.Q9 = report.CheckResult{
			Status: report.StatusFail,
			Tag:    "Invalid",
			Detail: report.Q9SoftwareEvidenceSignatureInvalid(),
		}
		reportInput.Q13 = report.CheckResult{
			Status: report.StatusFail,
			Tag:    "Unendorsed",
			Detail: report.Q13SoftwareEvidenceChainInvalid(),
		}
		return err
	} else {
		reportInput.Q9 = report.CheckResult{
			Status: report.StatusPass,
			Tag:    "Valid",
			Detail: report.Q9SoftwareEvidenceSignedByCert(getgcetrustedcertsOutput.Ak),
		}
		reportInput.Q13 = report.CheckResult{
			Status: report.StatusPass,
			Tag:    "Endorsed",
			Detail: report.Q13GcpSoftwareEvidenceChainValid(
				getgcetrustedcertsOutput.Ak,
				getgcetrustedcertsOutput.IntermediateCACertificate,
				getgcetrustedcertsOutput.RootCACertificate,
			),
		}
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
			Detail: report.Q18InstanceKeyBoundToSoftwareEvidence(getGceSnpEvidenceOutput.InstanceKeyCert),
		}
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
