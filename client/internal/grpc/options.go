package grpc

import (
	"crypto/tls"
	"crypto/x509"
	"time"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
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

	if cfg.VerifyTLS {
		if cfg.GrpcServerCertificate != nil {
			rootCaPool := x509.NewCertPool()
			rootCaPool.AddCert(cfg.GrpcServerCertificate)

			tlsCfg := &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    rootCaPool,
			}
			opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
		} else {
			opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(nil)))
		}
	} else {
		tlsCfg := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	}

	return opts
}
