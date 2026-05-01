package servecertify

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strconv"
	"sync"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
	pb "gitlab.com/dpss-inesc-id/achilles-cvm/client/pb/evident_protocol/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func Serve(port int, caCert []*x509.Certificate, caKey *ecdsa.PrivateKey, tlsConfig *tls.Config, interactive bool) error {
	log.Get().Debugf("starting certificate issuer/verifier server on port %d", port)
	log.Get().Debugf("configured CA certificates: %d", len(caCert))

	if interactive {
		log.Get().Info("interactive mode enabled: certificate issuance requires manual approval")
	}

	serverOptions := make([]grpc.ServerOption, 0, 2)
	if tlsConfig != nil {
		creds := credentials.NewTLS(tlsConfig)
		serverOptions = append(serverOptions, grpc.Creds(creds))
		log.Get().Debug("grpc server initialized with TLS credentials")
	} else {
		log.Get().Debug("grpc server initialized without TLS")
	}

	if interactive {
		var certIssueMutex sync.Mutex
		serverOptions = append(serverOptions, grpc.UnaryInterceptor(certificateIssueMutexInterceptor(&certIssueMutex)))
	}

	server := grpc.NewServer(serverOptions...)

	certIssuerVerifierService := NewCertificateIssuerVerifierServiceImpl(caCert, caKey, interactive)
	pb.RegisterCertificateIssuerVerifierServiceServer(server, certIssuerVerifierService)
	log.Get().Debug("certificate issuer/verifier service registered")

	listener, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return err
	}
	log.Get().Debugf("listening on %s", listener.Addr().String())

	return server.Serve(listener)
}

func certificateIssueMutexInterceptor(mu *sync.Mutex) grpc.UnaryServerInterceptor {
	certificateIssueMethod := "/" + pb.CertificateIssuerVerifierService_ServiceDesc.ServiceName + "/RequestInstanceKeyAttestationCertificate"
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if info.FullMethod == certificateIssueMethod {
			mu.Lock()
			defer mu.Unlock()
		}
		return handler(ctx, req)
	}
}
