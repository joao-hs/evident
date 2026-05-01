package servecertify

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strconv"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
	pb "gitlab.com/dpss-inesc-id/achilles-cvm/client/pb/evident_protocol/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func Serve(port int, caCert []*x509.Certificate, caKey *ecdsa.PrivateKey, tlsConfig *tls.Config) error {
	log.Get().Debugf("starting certificate issuer/verifier server on port %d", port)
	log.Get().Debugf("configured CA certificates: %d", len(caCert))

	var server *grpc.Server
	if tlsConfig != nil {
		creds := credentials.NewTLS(tlsConfig)
		server = grpc.NewServer(grpc.Creds(creds))
		log.Get().Debug("grpc server initialized with TLS credentials")
	} else {
		server = grpc.NewServer()
		log.Get().Debug("grpc server initialized without TLS")
	}

	certIssuerVerifierService := NewCertificateIssuerVerifierServiceImpl(caCert, caKey)
	pb.RegisterCertificateIssuerVerifierServiceServer(server, certIssuerVerifierService)
	log.Get().Debug("certificate issuer/verifier service registered")

	listener, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return err
	}
	log.Get().Debugf("listening on %s", listener.Addr().String())

	return server.Serve(listener)
}
