package report

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"math/big"
	"net/netip"
	"time"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
)

const skippedDetail = "Skipped: Could not be evaluated due to a prior check failure."

func skippedCheck() CheckResult {
	return CheckResult{
		Status: StatusSkip,
		Tag:    "Skipped",
		Detail: skippedDetail,
	}
}

// NewDefaultReportInput returns a ReportInput with all questions initialized as "Skipped".
func NewDefaultReportInput(ip netip.Addr, cloudProvider domain.CloudServiceProvider) ReportInput {
	s := skippedCheck()
	return ReportInput{
		IpAddress:     ip.String(),
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		CloudProvider: cloudProvider.String(),
		ClientVersion: "v0.1.0", // TODO: set dynamically based on build info

		Q1:  s,
		Q2:  s,
		Q3:  s,
		Q4:  s,
		Q5:  s,
		Q6:  s,
		Q7:  s,
		Q8:  s,
		Q9:  s,
		Q10: s,
		Q11: s,
		Q12: s,
		Q13: s,
		Q14: s,
		Q15: s,
		Q16: s,
		Q17: s,
		Q18: s,
	}
}

func base62EncodeSha256(input []byte) string {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	hash := sha256.Sum256(input)
	var result []byte
	num := new(big.Int).SetBytes(hash[:])

	zero := big.NewInt(0)
	base := big.NewInt(62)

	for num.Cmp(zero) > 0 {
		remainder := new(big.Int)
		num.DivMod(num, base, remainder)
		result = append(result, alphabet[remainder.Int64()])
	}

	// Reverse the result (standard for base conversion)
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	str := string(result)
	if len(str) > 12 {
		return str[:12]
	}
	for len(str) < 12 {
		str = "0" + str
	}
	return str
}

// publicKeyToID generates a short identifier string for a given public key, suitable for display in the report.
func publicKeyToID(key crypto.PublicKey) string {
	keyBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "(error marshaling key)"
	}
	return base62EncodeSha256(keyBytes)
}

// certificateToID generates a short identifier string for a given x509 certificate, suitable for display in the report.
func certificateToID(cert *x509.Certificate) string {
	key := cert.PublicKey
	return publicKeyToID(key)
}

func Q1AdditionalArtifactsRetrieved(fromServer bool) string {
	if fromServer {
		return "Yes, the additional artifacts bundle was fetched from the Evident server."
	}
	return "No, the additional artifacts bundle was not fetched from the Evident server. It was provided directly to the client (servecertify execution mode)."
}

func Q2AdditionalArtifactsSignatureValid(instanceCert *x509.Certificate) string {
	return fmt.Sprintf(
		"Yes, the additional artifacts bundle was correctly signed by the instance key identified by <code>%s</code>.",
		certificateToID(instanceCert),
	)
}

func Q2AdditionalArtifactsSignatureInvalid() string {
	return "No, the additional artifacts bundle signature is invalid. The bundle may have been tampered with or did not originate from the expected instance."
}

func Q3AdditionalArtifactsContentsValid() string {
	return "Yes, all contents of the additional artifacts bundle are structurally valid and complete."
}

func Q3AdditionalArtifactsContentsInvalid() string {
	return "No, the additional artifacts bundle contents are malformed or incomplete."
}

func Q4EvidenceBundleRetrieved() string {
	return "Yes, the evidence bundle was fetched from the Evident server."
}

func Q4EvidenceBundleNotRetrieved() string {
	return "No, the evidence bundle could not be fetched due to an error."
}

func Q5EvidenceBundleSignatureValid(instanceKey *x509.Certificate) string {
	return fmt.Sprintf(
		"Yes, the evidence bundle was correctly signed by the instance key identified by <code>%s</code>.",
		certificateToID(instanceKey),
	)
}

func Q5EvidenceBundleSignatureInvalid() string {
	return "No, the evidence bundle signature is invalid. The bundle may have been tampered with or did not originate from the expected instance."
}

func Q6HardwareEvidencePresentValidFormat() string {
	return "Yes, the evidence bundle includes an AMD SEV-SNP attestation report with the correct format."
}

func Q6HardwareEvidenceMissingOrInvalidFormat() string {
	return "No, the evidence bundle does not include a hardware evidence item, or the included item is not an AMD SEV-SNP attestation report with the correct format."
}

func Q7SoftwareEvidencePresentValidFormat() string {
	return "Yes, the evidence bundle includes a TPM quote with the correct format."
}

func Q7SoftwareEvidenceMissingOrInvalidFormat() string {
	return "No, the evidence bundle does not include a software evidence item, or the included item is not a TPM quote with the correct format."
}

func Q8HardwareEvidenceSignedBy(key *x509.Certificate) string {
	return fmt.Sprintf(
		"Yes, the AMD SEV-SNP attestation report is correctly signed by a key identified by <code>%s</code>.",
		certificateToID(key),
	)
}

func Q8HardwareEvidenceSignatureInvalid() string {
	return "No, the AMD SEV-SNP attestation report signature is invalid. The report may not be genuine or may have been tampered with."
}

func Q9SoftwareEvidenceSignedBy(key crypto.PublicKey) string {
	return fmt.Sprintf(
		"Yes, the TPM quote is correctly signed by a key identified by <code>%s</code>.",
		publicKeyToID(key),
	)
}

func Q9SoftwareEvidenceSignedByCert(keyCert *x509.Certificate) string {
	return fmt.Sprintf(
		"Yes, the TPM quote is correctly signed by a key identified by <code>%s</code>.",
		certificateToID(keyCert),
	)
}

func Q9SoftwareEvidenceSignatureInvalid() string {
	return "No, the TPM quote signature is invalid. The quote may not be genuine or may have been tampered with."
}

func Q10ProcessorModel(model string) string {
	return model
}

func Q11HardwareEvidenceChainValid(signingKeyType string, signingKeyCert *x509.Certificate, endorsingKeyType string, endorsingKeyCert *x509.Certificate, arkCert *x509.Certificate) string {
	return fmt.Sprintf(
		"Yes, the AMD SEV-SNP attestation report is signed by %s identified by <code>%s</code>, endorsed by %s identified by <code>%s</code>, which is endorsed by ARK identified by <code>%s</code>.",
		signingKeyType, certificateToID(signingKeyCert), endorsingKeyType, certificateToID(endorsingKeyCert), certificateToID(arkCert),
	)
}

func Q11HardwareEvidenceChainInvalid() string {
	return "No, the signing key does not chain back to AMD's root of trust. The attestation report may not be genuine or may have been tampered with."
}

func Q12HardwareEvidenceFresh() string {
	return "Yes, the unique identifier generated by the client matches the identifier included in the AMD SEV-SNP attestation report."
}

func Q12HardwareEvidenceNotFresh() string {
	return "No, the identifiers do not match. The attestation report may be stale or replayed."
}

func Q13GcpSoftwareEvidenceChainValid(akCert, intermediateCert, rootCert *x509.Certificate) string {
	return fmt.Sprintf(
		"Yes, the TPM quote is signed by a key identified by <code>%s</code>, endorsed by an intermediate key identified by <code>%s</code>, which is endorsed by the Google Root key identified by <code>%s</code>.",
		certificateToID(akCert), certificateToID(intermediateCert), certificateToID(rootCert),
	)
}

func Q13AwsSoftwareEvidenceChainValid(akKey, ekKey crypto.PublicKey) string {
	return fmt.Sprintf(
		"Yes, the key identified by <code>%s</code> (AK) is proven to be co-resident with a key identified by <code>%s</code> (EK), and that EK matches the value retrieved from the AWS API.",
		publicKeyToID(akKey), publicKeyToID(ekKey),
	)
}

func Q13AwsDoesNotEndorseWithoutInstanceID() string {
	return "No, AWS does not endorse the TPM quote without an instance ID. The quote may be missing necessary information to verify its origin."
}

func Q13SoftwareEvidenceChainInvalid() string {
	return "No, the signing key does not chain back to the cloud provider's root of trust. The TPM quote may not be genuine or may have been tampered with."
}

func Q14SoftwareEvidenceFresh() string {
	return "Yes, the nonce generated by the client matches the nonce included in the TPM quote."
}

func Q14SoftwareEvidenceNotFresh() string {
	return "No, the nonces do not match. The TPM quote may be stale or replayed."
}

func Q15AwsHardwareMeasurementsMatch() string {
	return "Yes, the measurements match the expected values derived from the release binary in <a href=\"https://github.com/aws/uefi\">github.com/aws/uefi</a>. The instance VM firmware matches the released version."
}

func Q15GcpHardwareMeasurementsMatch() string {
	return "Yes, the measurements match the expected values derived from the firmware binary retrieved and endorsed by Google Cloud. The instance's VM firmware matches the endorsed version."
}

func Q15HardwareMeasurementsMismatch() string {
	return "No, the measurements do not match the expected values."
}

func Q15AwsKnownIssue() string {
	return "No, this matches the known issue <a href=\"https://github.com/aws/uefi/issues/19\">github.com/aws/uefi/issues/19</a>. It may indicate a version mismatch between the published firmware and the production firmware."
}

func Q16SoftwareMeasurementsMatch() string {
	return "Yes, the PCR digest (PCRs 4, 11, 12) matches the expected value provided as input. If derived from the deployed VM image, this confirms the kernel, filesystem, and services at boot time correspond exactly to the expected software components."
}

func Q16SoftwareMeasurementsMismatch() string {
	return "No, the PCR digest does not match. The VM image may have been tampered with or does not match the expected software."
}

func Q17InstanceKeyBoundToHardwareEvidence(keyCert *x509.Certificate) string {
	return fmt.Sprintf(
		"Yes, the key identified by <code>%s</code> is incorporated into the hardware evidence. An instance with unexpected firmware measured at boot time could not generate the same result.",
		certificateToID(keyCert),
	)
}

func Q17InstanceKeyNotBoundToHardwareEvidence() string {
	return "No, the instance key is not bound to the hardware evidence."
}

func Q18InstanceKeyBoundToSoftwareEvidence(key *x509.Certificate) string {
	return fmt.Sprintf(
		"Yes, the key identified by <code>%s</code> is incorporated into the software evidence. An instance with unexpected software measured at boot time could not generate the same result.",
		certificateToID(key),
	)
}

func Q18InstanceKeyNotBoundToSoftwareEvidence() string {
	return "No, the instance key is not bound to the software evidence."
}
