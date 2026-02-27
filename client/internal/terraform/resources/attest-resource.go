package resources

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/int32validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/mapvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int32default"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/terraform/adapters/attest"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/terraform/utils"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/terraform/validators"
)

const (
	// source: https://www.ditig.com/validating-ipv4-and-ipv6-addresses-with-regexp
	_IP_V4_OR_V6_REGEX = `^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])|(([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,7}:|:(:[0-9A-Fa-f]{1,4}){1,7}|([0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,5}(:[0-9A-Fa-f]{1,4}){1,2}|([0-9A-Fa-f]{1,4}:){1,4}(:[0-9A-Fa-f]{1,4}){1,3}|([0-9A-Fa-f]{1,4}:){1,3}(:[0-9A-Fa-f]{1,4}){1,4}|([0-9A-Fa-f]{1,4}:){1,2}(:[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:(:[0-9A-Fa-f]{1,4}){1,6}|:(:[0-9A-Fa-f]{1,4}){1,6}))$`
)

type AttestResourceModel struct {
	ID                     types.String `tfsdk:"id"`
	CloudServiceProvider   types.String `tfsdk:"csp"`
	SecureHardwarePlatform types.String `tfsdk:"hardware_platform"`
	MachineType            types.String `tfsdk:"machine_type"`
	VirtualCoreCount       types.Int32  `tfsdk:"core_count"`
	EvidentServerEndpoints types.Map    `tfsdk:"endpoints"`
	TimeoutSec             types.Int32  `tfsdk:"timeout_sec"`
	ExpectedPCRsJson       types.String `tfsdk:"expected_pcrs"`
	AttestationResults     types.Map    `tfsdk:"attestation_results"`
}

type attestResource struct{}

func NewAttestResource() resource.Resource {
	return &attestResource{}
}

func (a *attestResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_attest"
}

func (a *attestResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
			},
			"csp": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Validators: []validator.String{
					stringvalidator.OneOfCaseInsensitive(
						"AWS",
						"Azure",
						"GCP",
					),
					stringvalidator.ExactlyOneOf(
						path.MatchRoot("csp"),
						path.MatchRoot("machine_type"),
					),
					stringvalidator.AlsoRequires(
						path.MatchRoot("hardware_platform"),
						path.MatchRoot("core_count"),
					),
				},
			},
			"hardware_platform": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Validators: []validator.String{
					stringvalidator.OneOfCaseInsensitive(
						"AMD SEV-SNP",
						"Intel TDX",
					),
					stringvalidator.ExactlyOneOf(
						path.MatchRoot("hardware_platform"),
						path.MatchRoot("machine_type"),
					),
					stringvalidator.AlsoRequires(
						path.MatchRoot("csp"),
						path.MatchRoot("core_count"),
					),
				},
			},
			"core_count": schema.Int32Attribute{
				Optional: true,
				Computed: true,
				Validators: []validator.Int32{
					int32validator.AtLeast(1),
					int32validator.ExactlyOneOf(
						path.MatchRoot("core_count"),
						path.MatchRoot("machine_type"),
					),
					int32validator.AlsoRequires(
						path.MatchRoot("csp"),
						path.MatchRoot("hardware_platform"),
					),
				},
			},
			"machine_type": schema.StringAttribute{
				Optional: true,
				Validators: []validator.String{
					validators.NewCSPMachineTypeValidator(),
				},
			},
			"endpoints": schema.MapAttribute{
				Required:    true,
				ElementType: types.Int32Type,
				Validators: []validator.Map{
					mapvalidator.KeysAre(
						stringvalidator.RegexMatches(
							regexp.MustCompile(_IP_V4_OR_V6_REGEX),
							"must be a valid IPv4 or IPv6 address",
						),
					),
					mapvalidator.ValueInt32sAre(
						int32validator.Between(1, 65535),
					),
				},
			},
			"timeout_sec": schema.Int32Attribute{
				Optional: true,
				Computed: true,
				Default:  int32default.StaticInt32(5 * 60), // 5 minutes
				Validators: []validator.Int32{
					int32validator.AtLeast(1),
				},
			},
			"expected_pcrs": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					&expectedPCRsJsonValidator{},
				},
			},
			"attestation_results": schema.MapAttribute{
				Computed:    true,
				ElementType: types.StringType,
			},
		},
	}
}

func (a *attestResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan AttestResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	planPtr := &plan
	defer func() {
		planPtr.ID = types.StringValue(uuid.NewString())
		resp.Diagnostics.Append(resp.State.Set(ctx, planPtr)...)
	}()

	timedCtx, cancel := context.WithTimeout(ctx, time.Duration(plan.TimeoutSec.ValueInt32())*time.Second)
	defer cancel()

	var endpoints map[string]int32
	resp.Diagnostics.Append(plan.EvidentServerEndpoints.ElementsAs(ctx, &endpoints, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, fmt.Sprintf("Waiting for %d seconds", plan.TimeoutSec.ValueInt32()))

	err := utils.WaitForPort(timedCtx, endpoints)
	if err != nil {
		resp.Diagnostics.AddError("Error waiting for ports to open", err.Error())
		return
	}

	results, err := attest.AttestTargets(ctx, endpoints, uint8(plan.VirtualCoreCount.ValueInt32()), plan.SecureHardwarePlatform.ValueString(), plan.CloudServiceProvider.ValueString(), []byte(plan.ExpectedPCRsJson.ValueString()))
	if err != nil {
		resp.Diagnostics.AddError("Error while attesting targets", err.Error())
		return
	}

	resultsReasons := make(map[string]string)
	for ip, err := range results {
		if err == nil {
			resultsReasons[ip] = "Successfully attested"
		} else {
			resultsReasons[ip] = err.Error()
		}
	}

	mapValue, diags := types.MapValueFrom(ctx, types.StringType, resultsReasons)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.AttestationResults = mapValue
}

func (a *attestResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state AttestResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (a *attestResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var (
		state AttestResourceModel
		plan  AttestResourceModel
	)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var (
		statePtr = &state
		planPtr  = &plan
	)
	defer func() {
		planPtr.ID = statePtr.ID
		resp.Diagnostics.Append(resp.State.Set(ctx, planPtr)...)
	}()

	timedCtx, cancel := context.WithTimeout(ctx, time.Duration(plan.TimeoutSec.ValueInt32())*time.Second)
	defer cancel()

	var (
		newEndpoints map[string]int32
	)
	resp.Diagnostics.Append(plan.EvidentServerEndpoints.ElementsAs(ctx, &newEndpoints, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := utils.WaitForPort(timedCtx, newEndpoints)
	if err != nil {
		resp.Diagnostics.AddError("Error waiting for ports to open", err.Error())
		return
	}

	results, err := attest.AttestTargets(ctx, newEndpoints, uint8(plan.VirtualCoreCount.ValueInt32()), plan.SecureHardwarePlatform.ValueString(), plan.CloudServiceProvider.ValueString(), []byte(plan.ExpectedPCRsJson.ValueString()))
	if err != nil {
		resp.Diagnostics.AddError("Error while attesting targets", err.Error())
		return
	}

	resultsReasons := make(map[string]string)
	for ip, err := range results {
		if err == nil {
			resultsReasons[ip] = "Successfully attested"
		} else {
			resultsReasons[ip] = err.Error()
		}
	}

	mapValue, diags := types.MapValueFrom(ctx, types.StringType, resultsReasons)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.AttestationResults = mapValue

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (a *attestResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// Do nothing
}

func (a *attestResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	tflog.Debug(ctx, "Running ModifyPlan")
	if req.Plan.Raw.IsNull() {
		return
	}

	tflog.Debug(ctx, "Getting plan")
	var plan AttestResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var (
		isCspSet         = !plan.CloudServiceProvider.IsNull() && !plan.CloudServiceProvider.IsUnknown()
		isHwPlatSet      = !plan.SecureHardwarePlatform.IsNull() && !plan.SecureHardwarePlatform.IsUnknown()
		isCoreCountSet   = !plan.VirtualCoreCount.IsNull() && !plan.VirtualCoreCount.IsUnknown()
		isMachineTypeSet = !plan.MachineType.IsNull() && !plan.MachineType.IsUnknown()
	)

	if !(isCspSet && isHwPlatSet && isCoreCountSet) && isMachineTypeSet {
		tflog.Debug(ctx, "Deriving from machine type")
		deriveFromMachineType(&plan)
		tflog.Debug(ctx, fmt.Sprintf("MachineType: %s -> %s, %s, %d", plan.MachineType.ValueString(), plan.CloudServiceProvider.ValueString(), plan.SecureHardwarePlatform.ValueString(), plan.VirtualCoreCount.ValueInt32()))
	}

	resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
}
