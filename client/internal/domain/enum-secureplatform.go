package domain

import (
	"encoding/json"
	"strings"
)

type SecureHardwarePlatform int

const (
	ENUM_SECURE_HARDWARE_PLATFORM_UNKNOWN SecureHardwarePlatform = iota
	ENUM_SECURE_HARDWARE_PLATFORM_AMD_SEV_SNP
	ENUM_SECURE_HARDWARE_PLATFORM_INTEL_TDX
)

const (
	_SECURE_HARDWARE_PLATFORM_UNKNOWN_STR                   = "Unknown secure hardware platform"
	_SECURE_HARDWARE_PLATFORM_AMD_SEV_SNP_STR               = "AMD SEV-SNP"
	_SECURE_HARDWARE_PLATFORM_AMD_SEV_SNP_ALTERNATIVE_1_STR = "SEV-SNP"
	_SECURE_HARDWARE_PLATFORM_AMD_SEV_SNP_ALTERNATIVE_2_STR = "SNP"
	_SECURE_HARDWARE_PLATFORM_INTEL_TDX_STR                 = "Intel TDX"
	_SECURE_HARDWARE_PLATFORM_INTEL_TDX_ALTERNATIVE_STR     = "TDX"
)

func (s SecureHardwarePlatform) String() string {
	return [...]string{
		_SECURE_HARDWARE_PLATFORM_UNKNOWN_STR,
		_SECURE_HARDWARE_PLATFORM_AMD_SEV_SNP_STR,
		_SECURE_HARDWARE_PLATFORM_INTEL_TDX_STR,
	}[s]
}

func (s *SecureHardwarePlatform) FromString(str string) SecureHardwarePlatform {
	return map[string]SecureHardwarePlatform{
		strings.ToLower(_SECURE_HARDWARE_PLATFORM_UNKNOWN_STR):                   ENUM_SECURE_HARDWARE_PLATFORM_UNKNOWN,
		strings.ToLower(_SECURE_HARDWARE_PLATFORM_AMD_SEV_SNP_STR):               ENUM_SECURE_HARDWARE_PLATFORM_AMD_SEV_SNP,
		strings.ToLower(_SECURE_HARDWARE_PLATFORM_AMD_SEV_SNP_ALTERNATIVE_1_STR): ENUM_SECURE_HARDWARE_PLATFORM_AMD_SEV_SNP,
		strings.ToLower(_SECURE_HARDWARE_PLATFORM_AMD_SEV_SNP_ALTERNATIVE_2_STR): ENUM_SECURE_HARDWARE_PLATFORM_AMD_SEV_SNP,
		strings.ToLower(_SECURE_HARDWARE_PLATFORM_INTEL_TDX_STR):                 ENUM_SECURE_HARDWARE_PLATFORM_INTEL_TDX,
		strings.ToLower(_SECURE_HARDWARE_PLATFORM_INTEL_TDX_ALTERNATIVE_STR):     ENUM_SECURE_HARDWARE_PLATFORM_INTEL_TDX,
	}[strings.ToLower(str)]
}

func (s *SecureHardwarePlatform) HardwareVendor() HardwareVendor {
	switch *s {
	case ENUM_SECURE_HARDWARE_PLATFORM_AMD_SEV_SNP:
		return HardwareVendor(ENUM_HARDWARE_VENDOR_AMD)
	case ENUM_SECURE_HARDWARE_PLATFORM_INTEL_TDX:
		return HardwareVendor(ENUM_HARDWARE_VENDOR_INTEL)
	default:
		return HardwareVendor(ENUM_HARDWARE_VENDOR_UNKNOWN)
	}
}

func (s SecureHardwarePlatform) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *SecureHardwarePlatform) UnmarshalJSON(data []byte) error {
	var val string
	err := json.Unmarshal(data, &val)
	if err != nil {
		return err
	}
	*s = s.FromString(val)
	return nil
}
