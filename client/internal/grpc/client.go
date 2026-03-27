package grpc

import (
	"context"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/config"
	pb "gitlab.com/dpss-inesc-id/achilles-cvm/client/pb/evident_protocol/v1"

	"google.golang.org/grpc"
)

type Client struct {
	conn   *grpc.ClientConn
	client pb.AttesterServiceClient
	cfg    *config.Config
}

func NewClient(cfg *config.Config) (*Client, error) {
	clientConn, err := grpc.NewClient(cfg.Addr, defaultDialOptions(cfg)...)
	if err != nil {
		return nil, err
	}

	return &Client{
		conn:   clientConn,
		client: pb.NewAttesterServiceClient(clientConn),
		cfg:    cfg,
	}, nil
}

func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) GetEvidence(ctx context.Context, req *pb.GetEvidenceRequest) (*pb.SignedEvidenceBundle, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	resp, err := retryingCall(ctx, c.client.GetEvidence, req, c.cfg.MaxRetries)
	if err == nil {
		return resp, nil
	}

	return nil, err
}

func (c *Client) GetAdditionalArtifacts(ctx context.Context, req *pb.GetAdditionalArtifactsRequest) (*pb.SignedAdditionalArtifactsBundle, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	resp, err := retryingCall(ctx, c.client.GetAdditionalArtifacts, req, c.cfg.MaxRetries)
	if err == nil {
		return resp, nil
	}

	return nil, err
}
