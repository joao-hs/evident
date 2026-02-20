package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
)

type expectedPCRsJsonValidator struct{}

func (v *expectedPCRsJsonValidator) Description(ctx context.Context) string {
	return "Ensures the string is valid JSON and matches the required internal schema."
}

func (v *expectedPCRsJsonValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v *expectedPCRsJsonValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsUnknown() || req.ConfigValue.IsNull() {
		return
	}

	// 1. Get the raw string
	content := req.ConfigValue.ValueString()

	// 2. Try to unmarshal into your ACTUAL Go struct
	var expectedPCRDigests domain.ExpectedPcrDigests
	if err := json.Unmarshal([]byte(content), &expectedPCRDigests); err != nil {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid JSON Format",
			fmt.Sprintf("The given expected PCRs file is not valid JSON: %s", err.Error()),
		)
		return
	}

	if len(expectedPCRDigests.Records) == 0 {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Incorrect JSON",
			"The given expected PCRs file does not contain any record",
		)
	}
}
