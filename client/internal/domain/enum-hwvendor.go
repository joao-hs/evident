package domain

import (
	"encoding/json"
	"strings"
)

type HardwareVendor int

const (
	ENUM_HARDWARE_VENDOR_UNKNOWN HardwareVendor = iota
	ENUM_HARDWARE_VENDOR_AMD
	ENUM_HARDWARE_VENDOR_INTEL
)

const (
	_HARDWARE_VENDOR_UNKNOWN_STR         = "Unknown hardware vendor"
	_HARDWARE_VENDOR_AMD_DEFAULT_STR     = "AMD"
	_HARDWARE_VENDOR_AMD_ALTERNATIVE_STR = "Advanced Micro Devices"
	_HARDWARE_VENDOR_INTEL_STR           = "Intel"
)

func (self HardwareVendor) String() string {
	return [...]string{
		_HARDWARE_VENDOR_UNKNOWN_STR,
		_HARDWARE_VENDOR_AMD_DEFAULT_STR,
		_HARDWARE_VENDOR_INTEL_STR,
	}[self]
}

func (self *HardwareVendor) FromString(str string) HardwareVendor {
	return map[string]HardwareVendor{
		strings.ToLower(_HARDWARE_VENDOR_UNKNOWN_STR):         ENUM_HARDWARE_VENDOR_UNKNOWN,
		strings.ToLower(_HARDWARE_VENDOR_AMD_DEFAULT_STR):     ENUM_HARDWARE_VENDOR_AMD,
		strings.ToLower(_HARDWARE_VENDOR_AMD_ALTERNATIVE_STR): ENUM_HARDWARE_VENDOR_AMD,
		strings.ToLower(_HARDWARE_VENDOR_INTEL_STR):           ENUM_HARDWARE_VENDOR_INTEL,
	}[strings.ToLower(str)]
}

func (self HardwareVendor) MarshalJSON() ([]byte, error) {
	return json.Marshal(self.String())
}

func (self *HardwareVendor) UnmarshalJSON(data []byte) error {
	var status string
	err := json.Unmarshal(data, &status)
	if err != nil {
		return err
	}
	*self = self.FromString(status)
	return nil
}
