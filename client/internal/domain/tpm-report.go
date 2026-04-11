package domain

import (
	"encoding/binary"
	"fmt"
)

type TpmReport struct {
	magic uint32

	attestationType uint16 // for quotes, should be 0x8018

	QualifiedSigner []byte

	ExtraData []byte

	ClockTime         uint64
	ClockResetCount   uint32
	ClockRestartCount uint32
	IsClockSafe       bool // true if TPM has not registered a future time in relation to the current time, false otherwise

	FirmwareVersion uint64

	PcrSelections []AttestedPcrSelectionData

	PcrDigest []byte
}

type AttestedPcrSelectionData struct {
	HashAlg   uint16 // SHA256 is 0x000B
	PcrSelect []byte // bit map of selected PCR
}

func NewTpmReport(quoted []byte) (*TpmReport, error) {
	if len(quoted) == 0 {
		return nil, fmt.Errorf("quoted data is empty")
	}

	quote := &TpmReport{}
	offset := 0

	quote.magic = binary.BigEndian.Uint32(quoted[offset : offset+4])
	offset += 4

	quote.attestationType = binary.BigEndian.Uint16(quoted[offset : offset+2])
	offset += 2

	if quote.attestationType != 0x8018 {
		return nil, fmt.Errorf("unsupported attestation type: expected 0x8018, got 0x%X", quote.attestationType)
	}

	qualifiedSignerNameSize := binary.BigEndian.Uint16(quoted[offset : offset+2])
	offset += 2

	quote.QualifiedSigner = make([]byte, qualifiedSignerNameSize)
	copy(quote.QualifiedSigner, quoted[offset:offset+int(qualifiedSignerNameSize)])
	offset += int(qualifiedSignerNameSize)

	extraDataSize := binary.BigEndian.Uint16(quoted[offset : offset+2])
	offset += 2

	quote.ExtraData = make([]byte, extraDataSize)
	copy(quote.ExtraData, quoted[offset:offset+int(extraDataSize)])
	offset += int(extraDataSize)

	quote.ClockTime = binary.BigEndian.Uint64(quoted[offset : offset+8])
	offset += 8

	quote.ClockResetCount = binary.BigEndian.Uint32(quoted[offset : offset+4])
	offset += 4

	quote.ClockRestartCount = binary.BigEndian.Uint32(quoted[offset : offset+4])
	offset += 4

	quote.IsClockSafe = quoted[offset] == 0x1
	offset += 1

	quote.FirmwareVersion = binary.LittleEndian.Uint64(quoted[offset : offset+8])
	offset += 8

	pcrSelectCount := binary.BigEndian.Uint32(quoted[offset : offset+4])
	offset += 4

	quote.PcrSelections = make([]AttestedPcrSelectionData, pcrSelectCount)
	for i := range pcrSelectCount {
		selection := AttestedPcrSelectionData{}
		selection.HashAlg = binary.BigEndian.Uint16(quoted[offset : offset+2])
		offset += 2

		sizeOfSelect := quoted[offset]
		offset += 1

		selection.PcrSelect = make([]byte, sizeOfSelect)
		copy(selection.PcrSelect, quoted[offset:offset+int(sizeOfSelect)])
		offset += int(sizeOfSelect)

		quote.PcrSelections[i] = selection
	}

	pcrDigestSize := binary.BigEndian.Uint16(quoted[offset : offset+2])
	offset += 2

	quote.PcrDigest = make([]byte, pcrDigestSize)
	copy(quote.PcrDigest, quoted[offset:offset+int(pcrDigestSize)])
	offset += int(pcrDigestSize)

	return quote, nil
}
