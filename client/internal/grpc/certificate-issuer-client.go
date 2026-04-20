package grpc

import (
	"context"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/config"
	pb "gitlab.com/dpss-inesc-id/achilles-cvm/client/pb/evident_protocol/v1"
	"google.golang.org/grpc"
)

type CertificateIssuerVerifierServiceClient struct {
	conn   *grpc.ClientConn
	client pb.CertificateIssuerVerifierServiceClient
	cfg    *config.Config
}

func NewCertificateIssuerVerifierServiceClient(cfg *config.Config) (*CertificateIssuerVerifierServiceClient, error) {
	clientConn, err := grpc.NewClient(cfg.Addr, defaultDialOptions(cfg)...)
	if err != nil {
		return nil, err
	}

	return &CertificateIssuerVerifierServiceClient{
		conn:   clientConn,
		client: pb.NewCertificateIssuerVerifierServiceClient(clientConn),
		cfg:    cfg,
	}, nil
}

func (c *CertificateIssuerVerifierServiceClient) Close() error {
	return c.conn.Close()
}

func (c *CertificateIssuerVerifierServiceClient) SubmitPackage(ctx context.Context, req *pb.MinimalPackage) (*pb.SignedPackageSubmissionResult, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	resp, err := retryingCall(ctx, c.client.SubmitTrustedPackage, req, c.cfg.MaxRetries)
	if err == nil {
		return resp, nil
	}

	return nil, err
}
