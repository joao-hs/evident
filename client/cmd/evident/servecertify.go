package evident

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
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

	caCerts, err := x509.ParseCertificates(caCertBytes)
	if err != nil {
		return nil, err
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

	privateKey, err := x509.ParseECPrivateKey(privateKeyBytes)
	if err != nil {
		return &ecdsa.PrivateKey{}, err
	}

	return privateKey, nil
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
