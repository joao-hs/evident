package attest

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/netip"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/workflows"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/config"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/grpc"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/packager"
	pb "gitlab.com/dpss-inesc-id/achilles-cvm/client/pb/evident_protocol/v1"
)

type Verifier interface {
	Attest(
		targetAddr netip.Addr,
		targetPort uint16,
		optCpuCount *uint8,
		optInstanceID *string,
		optExpectedPCRs *domain.ExpectedPcrDigests,
		optAdditionalArtifactsBundle *pb.AdditionalArtifactsBundle,
	) error
}

type verifier struct {
	ctx            context.Context
	securePlatform domain.SecureHardwarePlatform
	cloudProvider  domain.CloudServiceProvider
}

func NewVerifier(securePlatform domain.SecureHardwarePlatform, cloudProvider domain.CloudServiceProvider) (Verifier, error) {
	return &verifier{
		ctx:            context.Background(),
		securePlatform: securePlatform,
		cloudProvider:  cloudProvider,
	}, nil
}

func NewVerifierWithContext(ctx context.Context, securePlatform domain.SecureHardwarePlatform, cloudProvider domain.CloudServiceProvider) (Verifier, error) {
	return &verifier{
		ctx:            ctx,
		securePlatform: securePlatform,
		cloudProvider:  cloudProvider,
	}, nil
}

func (v *verifier) Attest(targetAddr netip.Addr, targetPort uint16, optCpuCount *uint8, optInstanceID *string, optExpectedPCRs *domain.ExpectedPcrDigests, optAdditionalArtifactsBundle *pb.AdditionalArtifactsBundle) error {
	var (
		optPkgs packager.Packages = nil
		err     error
	)
	if optExpectedPCRs == nil {
		optPkgs, err = packager.LoadTrustedPackages()
		if err != nil {
			return fmt.Errorf("failed to load trusted packages: %w", err)
		}
	}

	switch v.securePlatform {
	case domain.ENUM_SECURE_HARDWARE_PLATFORM_AMD_SEV_SNP:
		return v.attestSNP(targetAddr, targetPort, optCpuCount, optInstanceID, optExpectedPCRs, optPkgs, optAdditionalArtifactsBundle)
	default:
		return fmt.Errorf("unsupported secure platform: %s", v.securePlatform)
	}
}

func (v *verifier) attestSNP(targetAddr netip.Addr, targetPort uint16, optCpuCount *uint8, optInstanceID *string, optExpectedPCRs *domain.ExpectedPcrDigests, optPkgs packager.Packages, optAdditionalArtifactsBundle *pb.AdditionalArtifactsBundle) error {
	switch v.cloudProvider {
	case domain.ENUM_CLOUD_SERVICE_PROVIDER_AWS:
		return v.attestSNPEC2(targetAddr, targetPort, optCpuCount, optInstanceID, optExpectedPCRs, optPkgs, optAdditionalArtifactsBundle)
	case domain.ENUM_CLOUD_SERVICE_PROVIDER_GCP:
		return v.attestSNPGCE(targetAddr, targetPort, optCpuCount, optExpectedPCRs, optPkgs, optAdditionalArtifactsBundle)
	default:
		return fmt.Errorf("unsupported cloud provider for SNP: %s", v.cloudProvider)
	}
}

func (v *verifier) attestSNPEC2(targetAddr netip.Addr, targetPort uint16, optCpuCount *uint8, optInstanceID *string, optExpectedPCRs *domain.ExpectedPcrDigests, optPkgs packager.Packages, optAdditionalArtifactsBundle *pb.AdditionalArtifactsBundle) error {
	cfg := config.DefaultConfig()

	cfg.Addr = netip.AddrPortFrom(targetAddr, targetPort).String()

	ok, err := useGrpcServerCertificate(&cfg, optAdditionalArtifactsBundle)
	if err != nil {
		return fmt.Errorf("failed to use gRPC server certificate: %w", err)
	}
	if ok {
		log.Get().Debugf("Using gRPC server certificate from additional artifacts bundle for TLS connection")
	}

	client, err := grpc.NewAttesterServiceClient(&cfg)
	if err != nil {
		return err
	}
	defer client.Close()

	return workflows.RunSnpEc2AttestationWorkflow(v.ctx, client, optCpuCount, optInstanceID, optExpectedPCRs, optPkgs, optAdditionalArtifactsBundle)
}

func (v *verifier) attestSNPGCE(targetAddr netip.Addr, targetPort uint16, optCpuCount *uint8, optExpectedPCRs *domain.ExpectedPcrDigests, optPkgs packager.Packages, optAdditionalArtifactsBundle *pb.AdditionalArtifactsBundle) error {
	cfg := config.DefaultConfig()

	cfg.Addr = netip.AddrPortFrom(targetAddr, targetPort).String()

	ok, err := useGrpcServerCertificate(&cfg, optAdditionalArtifactsBundle)
	if err != nil {
		return fmt.Errorf("failed to use gRPC server certificate: %w", err)
	}
	if ok {
		log.Get().Debugf("Using gRPC server certificate from additional artifacts bundle for TLS connection")
	}

	client, err := grpc.NewAttesterServiceClient(&cfg)
	if err != nil {
		return err
	}
	defer client.Close()

	return workflows.RunSnpGceAttestationWorkflow(v.ctx, client, optCpuCount, optExpectedPCRs, optPkgs, optAdditionalArtifactsBundle)
}

func useGrpcServerCertificate(cfg *config.Config, optAdditionalArtifactsBundle *pb.AdditionalArtifactsBundle) (bool, error) {
	if optAdditionalArtifactsBundle == nil {
		return false, nil
	}

	grpcServerCertificate := optAdditionalArtifactsBundle.GetGrpcServerCertificate()
	if grpcServerCertificate == nil {
		return false, nil
	}

	if grpcServerCertificate.Type != pb.CertificateType_CERTIFICATE_TYPE_X509 {
		return false, fmt.Errorf("unsupported gRPC server certificate type: %s", grpcServerCertificate.Type.String())
	}

	switch grpcServerCertificate.Encoding {
	case pb.CertificateEncoding_CERTIFICATE_ENCODING_PEM:
		block, _ := pem.Decode(grpcServerCertificate.Data)
		if block == nil {
			return false, fmt.Errorf("failed to parse gRPC server certificate: no PEM block found")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return false, fmt.Errorf("failed to parse gRPC server certificate: %w", err)
		}
		if cert == nil {
			return false, fmt.Errorf("failed to parse gRPC server certificate: no certificate found")
		}
		cfg.GrpcServerCertificate = cert
	case pb.CertificateEncoding_CERTIFICATE_ENCODING_DER:
		cert, err := x509.ParseCertificate(grpcServerCertificate.Data)
		if err != nil {
			return false, fmt.Errorf("failed to parse gRPC server certificate: %w", err)
		}
		if cert == nil {
			return false, fmt.Errorf("failed to parse gRPC server certificate: no certificate found")
		}
		cfg.GrpcServerCertificate = cert
	default:
		return false, fmt.Errorf("unsupported gRPC server certificate encoding: %s", grpcServerCertificate.Encoding.String())
	}

	return true, nil
}
