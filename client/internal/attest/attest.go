package attest

import (
	"context"
	"fmt"
	"net/netip"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/workflows"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/config"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/grpc"
)

type Attestor interface {
	Attest(
		targetAddr netip.Addr,
		targetPort uint16,
		cpuCount uint8,
		securePlatform domain.SecureHardwarePlatform,
		cloudProvider domain.CloudServiceProvider,
		expectedPCRs domain.ExpectedPcrDigests,
	) error
}

type attestor struct {
}

func NewAttestor() (Attestor, error) {
	return &attestor{}, nil
}

func (self *attestor) Attest(targetAddr netip.Addr, targetPort uint16, cpuCount uint8, securePlatform domain.SecureHardwarePlatform, cloudProvider domain.CloudServiceProvider, expectedPCRs domain.ExpectedPcrDigests) error {
	switch securePlatform {
	case domain.ENUM_SECURE_HARDWARE_PLATFORM_AMD_SEV_SNP:
		return self.attestSNP(targetAddr, targetPort, cpuCount, cloudProvider, expectedPCRs)
	default:
		return fmt.Errorf("unsupported secure platform: %s", securePlatform)
	}
}

func (self *attestor) attestSNP(targetAddr netip.Addr, targetPort uint16, cpuCount uint8, cloudProvider domain.CloudServiceProvider, expectedPCRs domain.ExpectedPcrDigests) error {
	switch cloudProvider {
	case domain.ENUM_CLOUD_SERVICE_PROVIDER_GCP:
		return self.attestSNPGCE(targetAddr, targetPort, cpuCount, expectedPCRs)
	default:
		return fmt.Errorf("unsupported cloud provider for SNP: %s", cloudProvider)
	}
}

func (self *attestor) attestSNPGCE(targetAddr netip.Addr, targetPort uint16, cpuCount uint8, expectedPCRs domain.ExpectedPcrDigests) error {
	cfg := config.DefaultConfig()

	cfg.Addr = netip.AddrPortFrom(targetAddr, targetPort).String()

	client, err := grpc.NewClient(&cfg)
	if err != nil {
		return err
	}
	defer client.Close()

	ctx := context.Background()
	defer ctx.Done()

	return workflows.RunSnpGceAttestationWorkflow(ctx, client, cpuCount, expectedPCRs)
}
