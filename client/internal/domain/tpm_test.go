package domain

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

const (
	tpmQuoteExample = "quote.msg"
)

func TestTpmQuoteParse(t *testing.T) {
	quotePath := filepath.Join("testdata", tpmQuoteExample)
	quoteBytes, err := os.ReadFile(quotePath)
	if err != nil {
		t.Fatalf("failed to read TPM quote: %v", err)
	}

	if len(quoteBytes) == 0 {
		t.Fatal("TPM quote is empty")
	}

	quote, err := NewTpmReport(quoteBytes)
	if err != nil {
		t.Fatalf("failed to parse TPM quote: %v", err)
	}

	if quote == nil {
		t.Fatal("parsed TPM quote is nil")
	}

	// following values are obtained from the TCG spec and
	// from running `tpm2_print -t TPMS_ATTEST quote.msg`

	expectedMagic := uint32(0xff544347) // 'TCG'
	if quote.magic != expectedMagic {
		t.Errorf("unexpected magic number: got 0x%X, want 0x%X", quote.magic, expectedMagic)
	}

	expectedAttestationType := uint16(0x8018) // TPM2_ST_ATTEST_QUOTE
	if quote.attestationType != expectedAttestationType {
		t.Errorf("unexpected attestation type: got 0x%X, want 0x%X", quote.attestationType, expectedAttestationType)
	}

	expectedQualifiedSigner, err := hex.DecodeString("000b5da02930eedd371c94d42145658cde96d4af72e39dd3854018604bf5628ef67e")
	if err != nil {
		panic(fmt.Sprintf("failed to decode expected QualifiedSigner: %v", err))
	}
	if !bytes.Equal(quote.QualifiedSigner, expectedQualifiedSigner) {
		t.Errorf("unexpected QualifiedSigner: got %s, want %s", hex.EncodeToString(quote.QualifiedSigner), hex.EncodeToString(expectedQualifiedSigner))
	}

	expectedExtraData, err := hex.DecodeString("a9b3484de75d04e238180925321c986bae493d85bbf925a1ae91e9df4933507d")
	if err != nil {
		panic(fmt.Sprintf("failed to decode expected ExtraData: %v", err))
	}
	if !bytes.Equal(quote.ExtraData, expectedExtraData) {
		t.Errorf("unexpected ExtraData: got %s, want %s", hex.EncodeToString(quote.ExtraData), hex.EncodeToString(expectedExtraData))
	}

	expectedClockTime := uint64(821776)
	if quote.ClockTime != expectedClockTime {
		t.Errorf("unexpected ClockTime: got %d, want %d", quote.ClockTime, expectedClockTime)
	}

	expectedClockResetTime := uint32(15)
	if quote.ClockResetCount != expectedClockResetTime {
		t.Errorf("unexpected ResetCount: got %d, want %d", quote.ClockResetCount, expectedClockResetTime)
	}

	expectedClockRestartCount := uint32(0)
	if quote.ClockRestartCount != expectedClockRestartCount {
		t.Errorf("unexpected RestartCount: got %d, want %d", quote.ClockRestartCount, expectedClockRestartCount)
	}

	expectedIsClockSafe := true
	if quote.IsClockSafe != expectedIsClockSafe {
		t.Errorf("unexpected IsClockSafe: got %v, want %v", quote.IsClockSafe, expectedIsClockSafe)
	}

	expectedFirmwareVersion := uint64(0x0028160011051620)
	if quote.FirmwareVersion != expectedFirmwareVersion {
		t.Errorf("unexpected FirmwareVersion: got 0x%X, want 0x%X", quote.FirmwareVersion, expectedFirmwareVersion)
	}

	expectedPcrSelectionsLen := 1
	if len(quote.PcrSelections) != expectedPcrSelectionsLen {
		t.Errorf("unexpected number of PCR selections: got %d, want %d", len(quote.PcrSelections), expectedPcrSelectionsLen)
	}

	expectedPcrSelectionHashAlg := uint16(0x000B) // SHA256
	if quote.PcrSelections[0].HashAlg != expectedPcrSelectionHashAlg {
		t.Errorf("unexpected PCR selection hash algorithm: got 0x%X, want 0x%X", quote.PcrSelections[0].HashAlg, expectedPcrSelectionHashAlg)
	}

	expectedSizeOfSelectionBitMap := 3
	if len(quote.PcrSelections[0].PcrSelect) != expectedSizeOfSelectionBitMap {
		t.Errorf("unexpected PCR size of selection bit map: got %d, want %d", len(quote.PcrSelections[0].PcrSelect), expectedSizeOfSelectionBitMap)
	}

	// byte 0: PCRs 0-7 Example: 0b0001_0101 = PCR 0, 2, and 4 are selected
	// byte 1: PCRs 8-15
	// byte 2: PCRs 16-23
	expectedPcrSelectionBitMap := []byte{0b0001_0000, 0b0001_1000, 0b0000_0000} // PCRs 4, 11, and 12 are selected
	if !bytes.Equal(quote.PcrSelections[0].PcrSelect, expectedPcrSelectionBitMap) {
		t.Errorf("unexpected PCR selection bit map: got %08b, want %08b", quote.PcrSelections[0].PcrSelect, expectedPcrSelectionBitMap)
	}

	expectedPcrDigest, err := hex.DecodeString("bfa2f0e31f5f19281d3dd2079e0b6cefed7d99c5ce35f20f8019654cedfa88f9")
	if err != nil {
		panic(fmt.Sprintf("failed to decode expected PCR digest: %v", err))
	}
	if !bytes.Equal(quote.PcrDigest, expectedPcrDigest) {
		t.Errorf("unexpected PCR digest: got %s, want %s", hex.EncodeToString(quote.PcrDigest), hex.EncodeToString(expectedPcrDigest))
	}
}
