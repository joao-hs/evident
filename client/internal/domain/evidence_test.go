package domain

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

// Test cases
func TestSnpHardwareEvidence(t *testing.T) {
	reportPath := filepath.Join("testdata", attestationReportExample)
	attestationReportBytes, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("failed to read attestation report: %v", err)
	}

	hardwareEvidence, err := NewAMDSEVSNPHardwareEvidence(AMDSEVSNPModel(ENUM_AMD_SEV_SNP_MODEL_MILAN), attestationReportBytes)
	if err != nil {
		t.Fatalf("failed to create SNP hardware evidence: %v", err)
	}

	if hardwareEvidence.SecureHardwarePlatform() != ENUM_SECURE_HARDWARE_PLATFORM_AMD_SEV_SNP {
		t.Errorf("Expected SecureHardwarePlatform to return the correct platform")
	}

	// mostly to check if the Report is accessible
	if hardwareEvidence.Report().VMPL != 0 {
		t.Errorf("Expected Report to return the correct VMPL; got %d, expected %d", hardwareEvidence.Report().VMPL, 0)
	}

	// mostly to check if the SignedRaw is accessible
	if hardwareEvidence.Raw().Algorithm() != x509.ECDSAWithSHA384 {
		t.Errorf("Expected Raw to return the correct signature algorithm; got %v, expected %v", hardwareEvidence.Raw().Algorithm(), x509.ECDSAWithSHA384)
	}
}
