package sanitize

import (
	"fmt"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
)

func SecurePlatform(securePlatformStr string) (domain.SecureHardwarePlatform, error) {
	var dummy *domain.SecureHardwarePlatform
	securePlatform := dummy.FromString(securePlatformStr)
	if securePlatform != domain.ENUM_SECURE_HARDWARE_PLATFORM_UNKNOWN {
		return securePlatform, nil
	}
	return domain.ENUM_SECURE_HARDWARE_PLATFORM_UNKNOWN, fmt.Errorf("invalid secure platform: %v", securePlatformStr)
}
