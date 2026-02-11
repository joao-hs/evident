package sanitize

import (
	"fmt"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
)

func SecurePlatform(securePlatform string) (domain.SecureHardwarePlatform, error) {
	switch securePlatform {
	case "snp":
		return domain.ENUM_SECURE_HARDWARE_PLATFORM_AMD_SEV_SNP, nil
	case "tdx":
		return domain.ENUM_SECURE_HARDWARE_PLATFORM_INTEL_TDX, nil
	default:
		return domain.ENUM_SECURE_HARDWARE_PLATFORM_UNKNOWN, fmt.Errorf("invalid secure platform: %v", securePlatform)
	}
}
