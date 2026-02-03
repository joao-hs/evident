package domain

import (
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"math/big"
	"slices"
)

const amdSevSnpAttestationReportBytes = 1184

type AmdSevSnpGuestPolicy struct {
	// Bits 7:0
	ABIMinor uint8 `json:"abi_minor"`
	// Bits 15:8
	ABIMajor uint8 `json:"abi_major"`
	// Bit 16
	SMTAllowed bool `json:"smt"`
	// Bit 17 (Reserved)

	// Bit 18
	MigrateMAAllowed bool `json:"migrate_ma"`
	// Bit 19
	DebugAllowed bool `json:"debug"`
	// Bit 20
	SingleSocketGuestActivation bool `json:"single_socket"`
	// Bit 21
	CXLAllowed bool `json:"cxl_allow"`
	// Bit 22
	MemAES256XTSRequired bool `json:"mem_aes_256_xts"`
	// Bit 23
	RAPLDisabled bool `json:"rapl_disabled"`
	// Bit 24
	CiphertextHidingDRAMRequired bool `json:"ciphertext_hiding_dram"`
	// Bits 63:25 (Reserved)

}

type AmdSevSnpPlatformInfo struct {
	// Bit 0
	SMTEnabled bool `json:"smt_en"`
	// Bit 1
	TSMEEnabled bool `json:"tsme_en"`
	// Bit 2
	ECCEnabled bool `json:"ecc_en"`
	// Bit 3
	RAPLDisabled bool `json:"rapl_dis"`
	// Bit 4
	CiphertextHidingDRAMEnabled bool `json:"ciphertext_hiding_dram_en"`
	// Bit 5
	AliasCheckComplete bool `json:"alias_check_complete"`
	// Bits 63:6 (Reserved)

}

type AmdSevSnpAttestationReport struct {
	// Byte Offset 00h, Bits 31:0
	Version uint32 `json:"version"`
	// Byte Offset 04h, Bits 31:0
	GuestSvn uint32 `json:"guest_svn"`
	// Byte Offset 08h, Bits 63:0
	GuestPolicy AmdSevSnpGuestPolicy `json:"guest_policy"`
	// Byte Offset 10h, Bits 127:0
	FamilyID [16]byte `json:"family_id"`
	// Byte Offset 20h, Bits 127:0
	ImageID [16]byte `json:"image_id"`
	// Byte Offset 30h, Bits 31:0
	VMPL uint32 `json:"vmpl"`
	// Byte Offset 34h, Bits 31:0
	SignatureAlgo uint32 `json:"signature_algo"`
	// Byte Offset 38h, Bits 63:0
	CurrentTCB uint64 `json:"current_tcb"`
	// Byte Offset 40h, Bits 63:0
	PlatformInfo AmdSevSnpPlatformInfo `json:"platform_info"`
	// Byte Offset 48h, Bits 0
	AuthorKeyPresent bool `json:"author_key_en"`
	// Byte Offset 48h, Bits 1
	MaskChipKey bool `json:"mask_chip_key"`
	// Byte Offset 48h, Bits 4:2
	SigningKey uint8 `json:"signing_key"`
	// Byte Offset 48h, Bits 31:5 (Reserved)
	// Byte Offset 4Ch, Bits 31:0 (Reserved)

	// Byte Offset 50h, Bits 511:0
	ReportData [64]byte `json:"report_data"`
	// Byte Offset 90h, Bits 383:0
	Measurement [48]byte `json:"measurement"`
	// Byte Offset C0h, Bits 255:0
	HostData [32]byte `json:"host_data"`
	// Byte Offset E0h, Bits 383:0
	IDKeyDigest [48]byte `json:"id_key_digest"`
	// Byte Offset 110h, Bits 383:0
	AuthorKeyDigest [48]byte `json:"author_key_digest"`
	// Byte Offset 140h, Bits 255:0
	ReportID [32]byte `json:"report_id"`
	// Byte Offset 160h, Bits 255:0
	ReportIDMA [32]byte `json:"report_id_ma"`
	// Byte Offset 180h, Bits 63:0
	ReportedTCB uint64 `json:"reported_tcb"`
	// Byte Offset 188h, Bits 7:0
	CPUIDFamID uint8 `json:"cpu_id_fam_id"`
	// Byte Offset 189h, Bits 7:0
	CPUIDModID uint8 `json:"cpu_id_mod_id"`
	// Byte Offset 18Ah, Bits 7:0
	CPUIDStep uint8 `json:"cpu_id_step"`
	// Byte Offset 18Bh-19Fh (Reserved)

	// Byte Offset 1A0h, Bits 511:0
	ChipID [64]byte `json:"chip_id"`
	// Byte Offset 1E0h, Bits 63:0
	CommittedTCB uint64 `json:"committed_tcb"`
	// Byte Offset 1E8h, Bits 7:0
	CurrentBuild uint8 `json:"current_build"`
	// Byte Offset 1E9h, Bits 7:0
	CurrentMinor uint8 `json:"current_minor"`
	// Byte Offset 1EAh, Bits 7:0
	CurrentMajor uint8 `json:"current_major"`
	// Byte Offset 1EBh, Bits 7:0 (Reserved)

	// Byte Offset 1ECh, Bits 7:0
	CommittedBuild uint8 `json:"committed_build"`
	// Byte Offset 1EDh, Bits 7:0
	CommittedMinor uint8 `json:"committed_minor"`
	// Byte Offset 1EEh, Bits 7:0
	CommittedMajor uint8 `json:"committed_major"`
	// Byte Offset 1EFh, Bits 7:0 (Reserved)

	// Byte Offset 1F0h, Bits 63:0
	LaunchTcb uint64 `json:"launch_tcb"`
	// Byte Offset 1F8h-29Fh (Reserved)

	// Byte Offset 2A0h-49Fh
	Signature [512]byte `json:"signature"`
}

func (*AmdSevSnpAttestationReport) ReportFrom() SecureHardwarePlatform {
	return SecureHardwarePlatform(ENUM_SECURE_HARDWARE_PLATFORM_AMD_SEV_SNP)
}

func parseAmdSevSnpGuestPolicy(data []byte) AmdSevSnpGuestPolicy {
	if len(data) != 8 {
		panic("invalid data length for AmdSevSnpGuestPolicy")
	}

	return AmdSevSnpGuestPolicy{
		ABIMinor:   data[0],
		ABIMajor:   data[1],
		SMTAllowed: data[2]&0b1 != byte(0), // Bit 16 is Bit 0 of data[2]
		// Bit 17 is reserved
		MigrateMAAllowed:             data[2]&0b100 != byte(0),       // Bit 18 is Bit 2 of data[2]
		DebugAllowed:                 data[2]&0b1000 != byte(0),      // Bit 19 is Bit 3 of data[2]
		SingleSocketGuestActivation:  data[2]&0b1_0000 != byte(0),    // Bit 20 is Bit 4 of data[2]
		CXLAllowed:                   data[2]&0b10_0000 != byte(0),   // Bit 21 is Bit 5 of data[2]
		MemAES256XTSRequired:         data[2]&0b100_0000 != byte(0),  // Bit 22 is Bit 6 of data[2]
		RAPLDisabled:                 data[2]&0b1000_0000 != byte(0), // Bit 23 is Bit 7 of data[2]
		CiphertextHidingDRAMRequired: data[3]&0b1 != byte(0),         // Bit 24 is Bit 0 of data[3]
	}
}

func parseAmdSevSnpPlatformInfo(data []byte) AmdSevSnpPlatformInfo {
	if len(data) != 8 {
		panic("invalid data length for AmdSevSnpPlatformInfo")
	}

	return AmdSevSnpPlatformInfo{
		SMTEnabled:                  data[0]&0b1 != byte(0),       // Bit 0 is Bit 0 of data[0]
		TSMEEnabled:                 data[0]&0b10 != byte(0),      // Bit 1 is Bit 1 of data[0]
		ECCEnabled:                  data[0]&0b100 != byte(0),     // Bit 2 is Bit 2 of data[0]
		RAPLDisabled:                data[0]&0b1000 != byte(0),    // Bit 3 is Bit 3 of data[0]
		CiphertextHidingDRAMEnabled: data[0]&0b1_0000 != byte(0),  // Bit 4 is Bit 4 of data[0]
		AliasCheckComplete:          data[0]&0b10_0000 != byte(0), // Bit 5 is Bit 5 of data[0]
	}
}

func NewAmdSevSnpAttestationReport(source []byte) (*AmdSevSnpAttestationReport, error) {
	if len(source) != amdSevSnpAttestationReportBytes {
		return nil, fmt.Errorf("invalid source length: expected %d, got %d", amdSevSnpAttestationReportBytes, len(source))
	}

	report := &AmdSevSnpAttestationReport{}

	report.Version = binary.LittleEndian.Uint32(source[0x0:0x4])

	report.GuestSvn = binary.LittleEndian.Uint32(source[0x4:0x8])

	report.GuestPolicy = parseAmdSevSnpGuestPolicy(source[0x8:0x10])

	copy(report.FamilyID[:], source[0x10:0x20])

	copy(report.ImageID[:], source[0x20:0x30])

	report.VMPL = binary.LittleEndian.Uint32(source[0x30:0x34])

	report.SignatureAlgo = binary.LittleEndian.Uint32(source[0x34:0x38])

	report.CurrentTCB = binary.LittleEndian.Uint64(source[0x38:0x40])

	report.PlatformInfo = parseAmdSevSnpPlatformInfo(source[0x40:0x48])

	report.AuthorKeyPresent = source[0x48]&0b1 != byte(0)

	report.MaskChipKey = source[0x48]&0b10 != byte(0)

	report.SigningKey = (source[0x48] >> 2) & 0b111

	copy(report.ReportData[:], source[0x50:0x90])

	copy(report.Measurement[:], source[0x90:0xC0])

	copy(report.HostData[:], source[0xC0:0xE0])

	copy(report.IDKeyDigest[:], source[0xE0:0x110])

	copy(report.AuthorKeyDigest[:], source[0x110:0x140])

	copy(report.ReportID[:], source[0x140:0x160])

	copy(report.ReportIDMA[:], source[0x160:0x180])

	report.ReportedTCB = binary.LittleEndian.Uint64(source[0x180:0x188])

	report.CPUIDFamID = source[0x188]

	report.CPUIDModID = source[0x189]

	report.CPUIDStep = source[0x18A]

	copy(report.ChipID[:], source[0x1A0:0x1E0])

	report.CommittedTCB = binary.LittleEndian.Uint64(source[0x1E0:0x1E8])

	report.CurrentBuild = source[0x1E8]

	report.CurrentMinor = source[0x1E9]

	report.CurrentMajor = source[0x1EA]

	report.CommittedBuild = source[0x1EC]

	report.CommittedMinor = source[0x1ED]

	report.CommittedMajor = source[0x1EE]

	report.LaunchTcb = binary.LittleEndian.Uint64(source[0x1F0:0x1F8])

	copy(report.Signature[:], source[0x2A0:0x4A0])

	return report, nil
}

func (*AmdSevSnpAttestationReport) SignedDataSlice(source []byte) []byte {
	if len(source) != amdSevSnpAttestationReportBytes {
		panic(fmt.Sprintf("invalid source length: expected %d, got %d", amdSevSnpAttestationReportBytes, len(source)))
	}

	return source[0x0:0x2A0]
}

func (*AmdSevSnpAttestationReport) SignatureSlice(source []byte) []byte {
	if len(source) != amdSevSnpAttestationReportBytes {
		panic(fmt.Sprintf("invalid source length: expected %d, got %d", amdSevSnpAttestationReportBytes, len(source)))
	}

	signatureField := source[0x2A0:0x4A0]

	rLittleEndianBytes := signatureField[0x00:0x48]
	sLittleEndianBytes := signatureField[0x48:0x90]

	var rBytes, sBytes [48]byte
	copy(rBytes[:], rLittleEndianBytes)
	copy(sBytes[:], sLittleEndianBytes)
	slices.Reverse(rBytes[:])
	slices.Reverse(sBytes[:])

	r := new(big.Int).SetBytes(rBytes[:])
	s := new(big.Int).SetBytes(sBytes[:])

	signatureBytes, err := asn1.Marshal(struct {
		R, S *big.Int
	}{r, s})

	if err != nil {
		panic(fmt.Sprintf("failed to marshal signature to ASN.1: %v", err))
	}

	return signatureBytes
}
