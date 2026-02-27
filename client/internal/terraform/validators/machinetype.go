package validators

import (
	"context"
	"fmt"
	"slices"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

type cspMachineTypeValidator struct {
	validTypesByCSP map[string][]string
}

func NewCSPMachineTypeValidator() validator.String {
	validTypes := map[string][]string{
		"GCP":   generateValidGCPTypes(),
		"AWS":   generateValidAWSTypes(),
		"Azure": generateValidAzureTypes(),
	}

	return cspMachineTypeValidator{
		validTypesByCSP: validTypes,
	}
}

func (c cspMachineTypeValidator) Description(_ context.Context) string {
	return "machine_type must be a valid confidential machine type for the specified cloud service provider"
}

func (c cspMachineTypeValidator) MarkdownDescription(ctx context.Context) string {
	return c.Description(ctx)
}

func (c cspMachineTypeValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	machineType := req.ConfigValue.ValueString();
	for _, validTypes := range c.validTypesByCSP {
		if slices.Contains(validTypes, machineType) {
			return
		}
	}

	resp.Diagnostics.AddAttributeError(req.Path, "Invalid machine_type", fmt.Sprintf("%q is not a supported machine type", machineType))
}

// According to https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/supported-configurations, accessed 2026-02-26
func generateValidGCPTypes() []string {
	var types []string

	add := func(families []string, sizes []int, suffix string) {
		for _, f := range families {
			for _, s := range sizes {
				t := f + "-" + fmt.Sprintf("%d", s)
				if suffix != "" {
					t += "-" + suffix
				}
				types = append(types, t)
			}
		}
	}

	// c4d-{standard,highcpu,highmem}-{2,4,8,16,32,48,64,96,192,384}
	add(
		[]string{"c4d-standard", "c4d-highcpu", "c4d-highmem"},
		[]int{2, 4, 8, 16, 32, 48, 64, 96, 192, 384},
		"",
	)

	// c4d-{standard,highmem}-{8,16,32,48,64,96,192,384}-lssd
	add(
		[]string{"c4d-standard", "c4d-highmem"},
		[]int{8, 16, 32, 48, 64, 96, 192, 384},
		"lssd",
	)

	// c3d-{standard,highcpu,highmem}-{4,8,16,30,60,90,180,360}
	add(
		[]string{"c3d-standard", "c3d-highcpu", "c3d-highmem"},
		[]int{4, 8, 16, 30, 60, 90, 180, 360},
		"",
	)

	// c3d-standard-{8,16,30,60,90,180,360}-lssd
	add(
		[]string{"c3d-standard"},
		[]int{8, 16, 30, 60, 90, 180, 360},
		"lssd",
	)

	// c3d-highmem-{8,16,30,60,90,180,360}-lssd
	add(
		[]string{"c3d-highmem"},
		[]int{8, 16, 30, 60, 90, 180, 360},
		"lssd",
	)

	// c2d-{standard,highcpu,highmem}-{2,4,8,16,32,56,112}
	add(
		[]string{"c2d-standard", "c2d-highcpu", "c2d-highmem"},
		[]int{2, 4, 8, 16, 32, 56, 112},
		"",
	)

	// n2d-{standard,highcpu}-{2,4,8,16,32,48,64,80,96,128,224}
	add(
		[]string{"n2d-standard", "n2d-highcpu"},
		[]int{2, 4, 8, 16, 32, 48, 64, 80, 96, 128, 224},
		"",
	)

	// n2d-highmem-{2,4,8,16,32,48,64,80,96}
	add(
		[]string{"n2d-highmem"},
		[]int{2, 4, 8, 16, 32, 48, 64, 80, 96},
		"",
	)

	return types
}

// According to `aws ec2 describe-instance-types --filters Name=processor-info.supported-features,Values=amd-sev-snp --query 'InstanceTypes[*].[InstanceType]' --output text | sort`, accessed 2026-02-26
func generateValidAWSTypes() []string {
	var types []string

	add := func(family string, sizes []string) {
		for _, s := range sizes {
			t := family + "." + s
			types = append(types, t)
		}
	}

	// c6a.{large,xlarge,2xlarge,4xlarge,8xlarge,12xlarge,16xlarge}
	add(
		"c6a",
		[]string{"large", "xlarge", "2xlarge", "4xlarge", "8xlarge", "12xlarge", "16xlarge"},
	)

	// m6a.{large,xlarge,2xlarge,4xlarge,8xlarge}
	add(
		"m6a",
		[]string{"large", "xlarge", "2xlarge", "4xlarge", "8xlarge"},
	)

	// r6a.{large,xlarge,2xlarge,4xlarge}
	add(
		"r6a",
		[]string{"large", "xlarge", "2xlarge", "4xlarge"},
	)

	return types
}

func generateValidAzureTypes() []string {
	return []string{}
}
