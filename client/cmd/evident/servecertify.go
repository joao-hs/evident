package evident

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/sanitize"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/servecertify"
)

var serveCertifyCmd = &cobra.Command{
	Use:   "serve-certify <port> <ca-cert> <ca-key> <grpc-cert> <grpc-key>",
	Short: "Issue certificates if the client can be remotely attested",

	Args: cobra.ExactArgs(5),

	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		setupLogger(cmd)
		debugPrintFlags(cmd)
	},

	RunE: func(cmd *cobra.Command, args []string) error {
		var err error

		port, err := sanitize.Port(args[0])
		if err != nil {
			return err
		}

		caCerts, err := validateCaCertPath(args[1])
		if err != nil {
			return err
		}

		caKey, err := validateCAKeyPath(args[2])
		if err != nil {
			return err
		}

		gRPCCertPath, err := validateGRPCCertPath(args[3])
		if err != nil {
			return err
		}

		gRPCKeyPath, err := validateGRPCKeyPath(args[4])
		if err != nil {
			return err
		}

		gRPCCert, err := tls.LoadX509KeyPair(gRPCCertPath, gRPCKeyPath)
		if err != nil {
			return err
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{gRPCCert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"h2"},
		}

		cmd.SilenceUsage = true

		return servecertify.Serve(port, caCerts, caKey, tlsConfig)
	},
}

func validateCaCertPath(path string) ([]*x509.Certificate, error) {
	absPath, err := validateToAbsFilepath(path, "CA cert path")
	if err != nil {
		return nil, err
	}

	caCertBytes, err := os.ReadFile(absPath)
	if err != nil {
		return nil, err
	}

	var caCerts []*x509.Certificate
	remaining := caCertBytes
	for {
		var block *pem.Block
		block, remaining = pem.Decode(remaining)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		caCerts = append(caCerts, cert)
	}

	if len(caCerts) == 0 {
		return nil, fmt.Errorf("no PEM certificates found in CA cert path")
	}

	return caCerts, nil
}

func validateCAKeyPath(path string) (*ecdsa.PrivateKey, error) {
	absPath, err := validateToAbsFilepath(path, "CA key path")
	if err != nil {
		return &ecdsa.PrivateKey{}, err
	}

	privateKeyBytes, err := os.ReadFile(absPath)
	if err != nil {
		return &ecdsa.PrivateKey{}, err
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyBytes)
	if err != nil {
		return &ecdsa.PrivateKey{}, err
	}

	ecdsaPrivateKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return &ecdsa.PrivateKey{}, fmt.Errorf("CA key is not an ECDSA private key")
	}

	return ecdsaPrivateKey, nil
}

func validateGRPCCertPath(path string) (string, error) {
	return validateToAbsFilepath(path, "gRPC cert path")
}

func validateGRPCKeyPath(path string) (string, error) {
	return validateToAbsFilepath(path, "gRPC key path")
}

func init() {
	rootCmd.AddCommand(serveCertifyCmd)
}
