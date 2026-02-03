package domain

import "encoding/json"

type SecureHardwarePlatform int

const (
	ENUM_SECURE_HARDWARE_PLATFORM_UNKNOWN SecureHardwarePlatform = iota
	ENUM_SECURE_HARDWARE_PLATFORM_AMD_SEV_SNP
	ENUM_SECURE_HARDWARE_PLATFORM_INTEL_TDX
)

const (
	_SECURE_HARDWARE_PLATFORM_UNKNOWN_STR     = "Unknown secure hardware platform"
	_SECURE_HARDWARE_PLATFORM_AMD_SEV_SNP_STR = "AMD SEV-SNP"
	_SECURE_HARDWARE_PLATFORM_INTEL_TDX_STR   = "Intel TDX"
)

func (self SecureHardwarePlatform) String() string {
	return [...]string{
		_SECURE_HARDWARE_PLATFORM_UNKNOWN_STR,
		_SECURE_HARDWARE_PLATFORM_AMD_SEV_SNP_STR,
		_SECURE_HARDWARE_PLATFORM_INTEL_TDX_STR,
	}[self]
}

func (self *SecureHardwarePlatform) FromString(status string) SecureHardwarePlatform {
	return map[string]SecureHardwarePlatform{
		_SECURE_HARDWARE_PLATFORM_UNKNOWN_STR:     ENUM_SECURE_HARDWARE_PLATFORM_UNKNOWN,
		_SECURE_HARDWARE_PLATFORM_AMD_SEV_SNP_STR: ENUM_SECURE_HARDWARE_PLATFORM_AMD_SEV_SNP,
		_SECURE_HARDWARE_PLATFORM_INTEL_TDX_STR:   ENUM_SECURE_HARDWARE_PLATFORM_INTEL_TDX,
	}[status]
}

func (self *SecureHardwarePlatform) HardwareVendor() HardwareVendor {
	switch *self {
	case ENUM_SECURE_HARDWARE_PLATFORM_AMD_SEV_SNP:
		return HardwareVendor(ENUM_HARDWARE_VENDOR_AMD)
	case ENUM_SECURE_HARDWARE_PLATFORM_INTEL_TDX:
		return HardwareVendor(ENUM_HARDWARE_VENDOR_INTEL)
	default:
		return HardwareVendor(ENUM_HARDWARE_VENDOR_UNKNOWN)
	}
}

func (self SecureHardwarePlatform) MarshalJSON() ([]byte, error) {
	return json.Marshal(self.String())
}

func (self *SecureHardwarePlatform) UnmarshalJSON(data []byte) error {
	var status string
	err := json.Unmarshal(data, &status)
	if err != nil {
		return err
	}
	*self = self.FromString(status)
	return nil
}
