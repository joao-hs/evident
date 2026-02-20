package resources

import (
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func deriveFromMachineType(plan *AttestResourceModel) {
	machineTypeString := plan.MachineType.ValueString()

	// TODO: other CSPs and more sturdy parsing
	// for now, we assume Google and AMD

	// 1. CSP: hardcoded (assumption)
	plan.CloudServiceProvider = types.StringValue("GCP")

	// 2. Secure Hardware Platform: hardcoded (assumption)
	plan.SecureHardwarePlatform = types.StringValue("AMD SEV-SNP")

	// 3. CPU count: probably not bullet proof
	parts := strings.Split(machineTypeString, "-")
	if len(parts) != 3 {
		panic("expected 3 parts")
	}

	coreCount, err := strconv.Atoi(parts[2])
	if err != nil {
		panic(err)
	}
	plan.VirtualCoreCount = types.Int32Value(int32(coreCount))
}
