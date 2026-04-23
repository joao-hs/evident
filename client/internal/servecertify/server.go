package servecertify

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strconv"

	pb "gitlab.com/dpss-inesc-id/achilles-cvm/client/pb/evident_protocol/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func Serve(port int, caCert []*x509.Certificate, caKey *ecdsa.PrivateKey, tlsConfig *tls.Config) error {

	creds := credentials.NewTLS(tlsConfig)
	server := grpc.NewServer(grpc.Creds(creds))

	certIssuerVerifierService, err := NewCertificateIssuerVerifierServiceImpl(caCert, caKey)
	if err != nil {
		return err
	}

	pb.RegisterCertificateIssuerVerifierServiceServer(server, certIssuerVerifierService)

	listener, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return err
	}

	return server.Serve(listener)
}
