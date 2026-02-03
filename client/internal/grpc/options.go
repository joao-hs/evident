package grpc

import (
	"time"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

func defaultDialOptions(cfg *config.Config) []grpc.DialOption {
	opts := []grpc.DialOption{
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  1 * time.Second,
				MaxDelay:   5 * time.Second,
				Multiplier: 1.6,
			},
			MinConnectTimeout: 30 * time.Second,
		}),
	}

	if cfg.UseTLS {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(nil)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	return opts
}
