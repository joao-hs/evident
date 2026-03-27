package config

import (
	"crypto/x509"
	"time"
)

type Config struct {
	Addr                  string
	Timeout               time.Duration
	VerifyTLS             bool
	GrpcServerCertificate *x509.Certificate
	MaxRetries            int
}

func DefaultConfig() Config {
	return Config{
		Addr:                  "localhost:5000",
		Timeout:               5 * time.Second,
		VerifyTLS:             false,
		GrpcServerCertificate: nil,
		MaxRetries:            3,
	}
}
