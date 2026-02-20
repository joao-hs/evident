package sanitize

import (
	"fmt"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
)

func CloudServiceProvider(cloudProviderStr string) (domain.CloudServiceProvider, error) {
	var dummy *domain.CloudServiceProvider
	cloudProvider := dummy.FromString(cloudProviderStr)
	if cloudProvider != domain.ENUM_CLOUD_SERVICE_PROVIDER_UNKNOWN {
		return cloudProvider, nil
	}
	return domain.ENUM_CLOUD_SERVICE_PROVIDER_UNKNOWN, fmt.Errorf("invalid cloud service provider: %v", cloudProviderStr)
}
