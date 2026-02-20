package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/terraform/resources"
)

type evidentProvider struct {
	version string
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &evidentProvider{
			version: version,
		}
	}
}

func (evidentProvider *evidentProvider) Configure(_ context.Context, _ provider.ConfigureRequest, _ *provider.ConfigureResponse) {
	// Do nothing
}

func (evidentProvider *evidentProvider) DataSources(context.Context) []func() datasource.DataSource {
	return nil
}

func (evidentProvider *evidentProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "evident"
	resp.Version = evidentProvider.version
}

func (evidentProvider *evidentProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		resources.NewAttestResource,
	}
}

func (evidentProvider *evidentProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{},
	}
}
