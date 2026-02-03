package domain

import (
	"bytes"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

const (
	attestationReportExample = "attestation-report.bin" // TODO: Get a better example
	nonceFileExample         = "nonce.bin"
	vcekExample              = "certs/vcek.der"
	askExample               = "certs/ask.pem"
	arkExample               = "certs/ark.pem"
)

func TestAmdSevAttestationReportParse(t *testing.T) {
	reportPath := filepath.Join("testdata", attestationReportExample)
	attestationReportBytes, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("failed to read attestation report: %v", err)
	}

	switch {
	case len(attestationReportBytes) == 0:
		t.Fatalf("attestation report is empty")
	case len(attestationReportBytes) != amdSevSnpAttestationReportBytes:
		t.Fatalf("invalid attestation report size: expected %d, got %d", amdSevSnpAttestationReportBytes, len(attestationReportBytes))
	}

	report, err := NewAmdSevSnpAttestationReport(attestationReportBytes)
	if err != nil {
		t.Fatalf("failed to parse attestation report: %v", err)
	}

	expectedVersion := 0x4
	if report.Version != uint32(expectedVersion) {
		t.Errorf("unexpected Version: got %d, want %d", report.Version, expectedVersion)
	}

	expectedGuestSvn := 0x0
	if report.GuestSvn != uint32(expectedGuestSvn) {
		t.Errorf("unexpected GuestSvn: got %d, want %d", report.GuestSvn, expectedGuestSvn)
	}

	expectedABIMajor := 0x0
	if report.GuestPolicy.ABIMajor != uint8(expectedABIMajor) {
		t.Errorf("unexpected GuestPolicy.ABIMajor: got %d, want %d", report.GuestPolicy.ABIMajor, expectedABIMajor)
	}

	expectedABIMinor := 0x0
	if report.GuestPolicy.ABIMinor != uint8(expectedABIMinor) {
		t.Errorf("unexpected GuestPolicy.ABIMinor: got %d, want %d", report.GuestPolicy.ABIMinor, expectedABIMinor)
	}

	expectedSMTAllowed := true
	if report.GuestPolicy.SMTAllowed != expectedSMTAllowed {
		t.Errorf("unexpected GuestPolicy.SMTAllowed: got %v, want %v", report.GuestPolicy.SMTAllowed, expectedSMTAllowed)
	}

	expectedMigrateMAAllowed := false
	if report.GuestPolicy.MigrateMAAllowed != expectedMigrateMAAllowed {
		t.Errorf("unexpected GuestPolicy.MigrateMAAllowed: got %v, want %v", report.GuestPolicy.MigrateMAAllowed, expectedMigrateMAAllowed)
	}

	expectedDebugAllowed := false
	if report.GuestPolicy.DebugAllowed != expectedDebugAllowed {
		t.Errorf("unexpected GuestPolicy.DebugAllowed: got %v, want %v", report.GuestPolicy.DebugAllowed, expectedDebugAllowed)
	}

	expectedSingleSocketGuestActivation := false
	if report.GuestPolicy.SingleSocketGuestActivation != expectedSingleSocketGuestActivation {
		t.Errorf("unexpected GuestPolicy.SingleSocketGuestActivation: got %v, want %v", report.GuestPolicy.SingleSocketGuestActivation, expectedSingleSocketGuestActivation)
	}

	expectedCXLAllowed := false
	if report.GuestPolicy.CXLAllowed != expectedCXLAllowed {
		t.Errorf("unexpected GuestPolicy.CXLAllowed: got %v, want %v", report.GuestPolicy.CXLAllowed, expectedCXLAllowed)
	}

	expectedMemAES256XTSRequired := false
	if report.GuestPolicy.MemAES256XTSRequired != expectedMemAES256XTSRequired {
		t.Errorf("unexpected GuestPolicy.MemAES256XTSRequired: got %v, want %v", report.GuestPolicy.MemAES256XTSRequired, expectedMemAES256XTSRequired)
	}

	expectedRAPLDisabled := false
	if report.GuestPolicy.RAPLDisabled != expectedRAPLDisabled {
		t.Errorf("unexpected GuestPolicy.RAPLDisabled: got %v, want %v", report.GuestPolicy.RAPLDisabled, expectedRAPLDisabled)
	}

	expectedCiphertextHidingDRAMRequired := false
	if report.GuestPolicy.CiphertextHidingDRAMRequired != expectedCiphertextHidingDRAMRequired {
		t.Errorf("unexpected GuestPolicy.CiphertextHidingDRAMRequired: got %v, want %v", report.GuestPolicy.CiphertextHidingDRAMRequired, expectedCiphertextHidingDRAMRequired)
	}

	expectedFamilyID := [16]byte{0x0}
	if !bytes.Equal(report.FamilyID[:], expectedFamilyID[:]) {
		t.Errorf("unexpected FamilyID: got %x, want %x", report.FamilyID, expectedFamilyID)
	}

	expectedImageID := [16]byte{0x0}
	if !bytes.Equal(report.ImageID[:], expectedImageID[:]) {
		t.Errorf("unexpected ImageID: got %x, want %x", report.ImageID, expectedImageID)
	}

	expectedVMPL := 0x0
	if report.VMPL != uint32(expectedVMPL) {
		t.Errorf("unexpected VMPL: got %d, want %d", report.VMPL, expectedVMPL)
	}

	expectedSignatureAlgo := 0x1
	if report.SignatureAlgo != uint32(expectedSignatureAlgo) {
		t.Errorf("unexpected SignatureAlgo: got %d, want %d", report.SignatureAlgo, expectedSignatureAlgo)
	}

	expectedCurrentTCB := uint64(0xdb19000000000004)
	if report.CurrentTCB != expectedCurrentTCB {
		t.Errorf("unexpected CurrentTCB: got %d, want %d", report.CurrentTCB, expectedCurrentTCB)
	}

	expectedPlatformInfoSmtEnabled := true
	if report.PlatformInfo.SMTEnabled != expectedPlatformInfoSmtEnabled {
		t.Errorf("unexpected PlatformInfo.SMTEnabled: got %v, want %v", report.PlatformInfo.SMTEnabled, expectedPlatformInfoSmtEnabled)
	}

	expectedPlatformInfoTSEnabled := false
	if report.PlatformInfo.TSMEEnabled != expectedPlatformInfoTSEnabled {
		t.Errorf("unexpected PlatformInfo.TSMEEnabled: got %v, want %v", report.PlatformInfo.TSMEEnabled, expectedPlatformInfoTSEnabled)
	}

	expectedPlatformInfoECCEnabled := true
	if report.PlatformInfo.ECCEnabled != expectedPlatformInfoECCEnabled {
		t.Errorf("unexpected PlatformInfo.ECCEnabled: got %v, want %v", report.PlatformInfo.ECCEnabled, expectedPlatformInfoECCEnabled)
	}

	expectedPlatformInfoRAPLDisabled := false
	if report.PlatformInfo.RAPLDisabled != expectedPlatformInfoRAPLDisabled {
		t.Errorf("unexpected PlatformInfo.RAPLDisabled: got %v, want %v", report.PlatformInfo.RAPLDisabled, expectedPlatformInfoRAPLDisabled)
	}

	expectedPlatformInfoCiphertextHidingDRAMEnabled := false
	if report.PlatformInfo.CiphertextHidingDRAMEnabled != expectedPlatformInfoCiphertextHidingDRAMEnabled {
		t.Errorf("unexpected PlatformInfo.CiphertextHidingDRAMEnabled: got %v, want %v", report.PlatformInfo.CiphertextHidingDRAMEnabled, expectedPlatformInfoCiphertextHidingDRAMEnabled)
	}

	expectedPlatformInfoAliasCheckComplete := true
	if report.PlatformInfo.AliasCheckComplete != expectedPlatformInfoAliasCheckComplete {
		t.Errorf("unexpected PlatformInfo.AliasCheckComplete: got %v, want %v", report.PlatformInfo.AliasCheckComplete, expectedPlatformInfoAliasCheckComplete)
	}

	expectedAuthorKeyPresent := false
	if report.AuthorKeyPresent != expectedAuthorKeyPresent {
		t.Errorf("unexpected AuthorKeyPresent: got %v, want %v", report.AuthorKeyPresent, expectedAuthorKeyPresent)
	}

}

func TestAmdSevAttestationReportVerifySignature(t *testing.T) {
	reportPath := filepath.Join("testdata", attestationReportExample)
	noncePath := filepath.Join("testdata", nonceFileExample)
	vcekPath := filepath.Join("testdata", vcekExample)

	attestationReportBytes, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("failed to read test data: %v", err)
	}

	certificateBytes, err := os.ReadFile(vcekPath)
	if err != nil {
		t.Fatalf("failed to read test data: %v", err)
	}

	nonceBytes, err := os.ReadFile(noncePath)
	if err != nil {
		t.Fatalf("failed to read test data: %v", err)
	}

	switch {
	case len(attestationReportBytes) == 0:
		t.Fatalf("attestation report is empty")
	case len(attestationReportBytes) != amdSevSnpAttestationReportBytes:
		t.Fatalf("invalid attestation report size: expected %d, got %d", amdSevSnpAttestationReportBytes, len(attestationReportBytes))
	case len(certificateBytes) == 0:
		t.Fatalf("certificate chain is empty")
	case len(nonceBytes) == 0:
		t.Fatalf("nonce is empty")
	case len(nonceBytes) < 64:
		nonceBytes = append(nonceBytes, bytes.Repeat([]byte{0}, 64-len(nonceBytes))...)
	case len(nonceBytes) > 64:
		t.Fatalf("nonce is too long")
	}

	report, err := NewAmdSevSnpAttestationReport(attestationReportBytes)
	if err != nil {
		t.Fatalf("failed to parse attestation report: %v", err)
	}

	if !bytes.Equal(report.ReportData[:], nonceBytes) {
		t.Fatalf("nonce does not match report data")
	}

	vcekCert, err := x509.ParseCertificate(certificateBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate chain: %v", err)
	}

	if vcekCert == nil {
		t.Fatalf("parsed certificate is nil")
	}

	certChain := NewCertChain(vcekCert)

	dummy := &AmdSevSnpAttestationReport{}
	signedRaw := SignedRawFromBytes(x509.ECDSAWithSHA384, dummy.SignedDataSlice(attestationReportBytes), dummy.SignatureSlice(attestationReportBytes), certChain)

	if signedRaw == nil {
		t.Fatalf("failed to create SignedRaw from attestation report")
	}

	ok, err := signedRaw.IsOk()
	if err != nil {
		t.Fatalf("failed to verify attestation report signature: %v", err)
	}

	if !ok {
		t.Fatalf("attestation report signature is not valid")
	}
}
