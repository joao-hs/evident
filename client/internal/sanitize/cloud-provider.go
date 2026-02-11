package sanitize

import (
	"fmt"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
)

func CloudServiceProvider(cloudProvider string) (domain.CloudServiceProvider, error) {
	switch cloudProvider {
	case "avm":
		return domain.ENUM_CLOUD_SERVICE_PROVIDER_AZURE, nil
	case "ec2":
		return domain.ENUM_CLOUD_SERVICE_PROVIDER_AWS, nil
	case "gce":
		return domain.ENUM_CLOUD_SERVICE_PROVIDER_GCP, nil
	default:
		return domain.ENUM_CLOUD_SERVICE_PROVIDER_UNKNOWN, fmt.Errorf("invalid cloud service provider: %v", cloudProvider)
	}
}
