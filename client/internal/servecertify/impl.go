package servecertify

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"time"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/crypto"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/sanitize"
	pb "gitlab.com/dpss-inesc-id/achilles-cvm/client/pb/evident_protocol/v1"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/proto"
)

type certificateIssuerVerifierServiceImpl struct {
	pb.UnimplementedCertificateIssuerVerifierServiceServer

	caCerts []*x509.Certificate
	caKey   *ecdsa.PrivateKey
}

func NewCertificateIssuerVerifierServiceImpl(caCerts []*x509.Certificate, caKey *ecdsa.PrivateKey) pb.CertificateIssuerVerifierServiceServer {
	return &certificateIssuerVerifierServiceImpl{
		caCerts: caCerts,
		caKey:   caKey,
	}
}

func (c *certificateIssuerVerifierServiceImpl) SubmitTrustedPackage(ctx context.Context, request *pb.Package) (*pb.SignedPackageSubmissionResult, error) {
	return nil, fmt.Errorf("not implemented")
}

func (c *certificateIssuerVerifierServiceImpl) RequestInstanceKeyAttestationCertificate(ctx context.Context, request *pb.SignedAdditionalArtifactsBundle) (*pb.SignedCertificateChain, error) {
	ok, err := crypto.VerifyDataSignature(request.SerializedAdditionalArtifactsBundle, request.Signature, request.SigningKey)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("signature verification failed")
	}

	clientPeer, ok := peer.FromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("failed to get client from context")
	}

	clientAddrStr, _, err := net.SplitHostPort(clientPeer.Addr.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse client address: %w", err)
	}

	targetAddr, err := sanitize.TargetIP(clientAddrStr)
	if err != nil {
		return nil, fmt.Errorf("failed to sanitize client address: %w", err)
	}

	var additionalArtifactsBundle pb.AdditionalArtifactsBundle
	err = proto.Unmarshal(request.SerializedAdditionalArtifactsBundle, &additionalArtifactsBundle)
	if err != nil {
		return nil, err
	}

	target := additionalArtifactsBundle.TargetType
	var verifier attest.Verifier
	switch target {
	case pb.TargetType_TARGET_TYPE_SNP_EC2:
		verifier, err = attest.NewVerifierWithContext(
			ctx,
			domain.SecureHardwarePlatform(domain.ENUM_SECURE_HARDWARE_PLATFORM_AMD_SEV_SNP),
			domain.CloudServiceProvider(domain.ENUM_CLOUD_SERVICE_PROVIDER_AWS),
		)
	case pb.TargetType_TARGET_TYPE_SNP_GCE:
		verifier, err = attest.NewVerifierWithContext(
			ctx,
			domain.SecureHardwarePlatform(domain.ENUM_SECURE_HARDWARE_PLATFORM_AMD_SEV_SNP),
			domain.CloudServiceProvider(domain.ENUM_CLOUD_SERVICE_PROVIDER_AWS),
		)
	default:
		return nil, fmt.Errorf("unsupported target type: %s", target.String())
	}
	if err != nil {
		return nil, err
	}

	err = verifier.Attest(
		targetAddr,
		5000,
		nil, // Option: None -> Derive CPU count
		nil, // Option: None -> Use trusted packages
		&additionalArtifactsBundle,
	)
	if err != nil {
		return nil, err
	}

	csr := additionalArtifactsBundle.GetInstanceCsr()
	if csr == nil {
		return nil, fmt.Errorf("missing CSR in additional artifacts bundle")
	}

	if csr.Encoding != pb.CSREncoding_CSR_ENCODING_PEM {
		return nil, fmt.Errorf("unsupported CSR encoding: %s", csr.Encoding.String())
	}

	if csr.Format != pb.CSRFormat_CSR_FORMAT_PKCS10 {
		return nil, fmt.Errorf("unsupported CSR format: %s", csr.Format.String())
	}

	certChain, err := c.issueCertificate(csr.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to issue certificate: %w", err)
	}

	certChainBytes, err := proto.Marshal(certChain)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificate chain: %w", err)
	}

	return &pb.SignedCertificateChain{
		SerializedCertificateChain: certChainBytes,
		Signature:                  nil, // TODO: sign the certificate chain
		SigningKey:                 nil, // TODO: include the signing key or its identifier
	}, nil
}

func (c *certificateIssuerVerifierServiceImpl) attestSnpEc2(ctx context.Context, targetAddr netip.Addr, targetPort uint16, additionalArtifactsBundle *pb.AdditionalArtifactsBundle) error {
	verifier, err := attest.NewVerifierWithContext(
		ctx,
		domain.SecureHardwarePlatform(domain.ENUM_SECURE_HARDWARE_PLATFORM_AMD_SEV_SNP),
		domain.CloudServiceProvider(domain.ENUM_CLOUD_SERVICE_PROVIDER_AWS),
	)
	if err != nil {
		return err
	}

	return verifier.Attest(targetAddr, targetPort, nil, nil, additionalArtifactsBundle)
}

func (c *certificateIssuerVerifierServiceImpl) attestSnpGce(ctx context.Context, targetAddr netip.Addr, targetPort uint16, additionalArtifactsBundle *pb.AdditionalArtifactsBundle) error {
	verifier, err := attest.NewVerifierWithContext(
		ctx,
		domain.SecureHardwarePlatform(domain.ENUM_SECURE_HARDWARE_PLATFORM_AMD_SEV_SNP),
		domain.CloudServiceProvider(domain.ENUM_CLOUD_SERVICE_PROVIDER_AWS),
	)
	if err != nil {
		return err
	}

	return verifier.Attest(targetAddr, targetPort, nil, nil, additionalArtifactsBundle)
}

func (c *certificateIssuerVerifierServiceImpl) issueCertificate(csrBytes []byte) (*pb.CertificateChain, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),

		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		EmailAddresses: csr.EmailAddresses,
		URIs:           csr.URIs,

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDer, err := x509.CreateCertificate(
		rand.Reader,
		template,
		c.caCerts[0],
		csr.PublicKey,
		c.caKey,
	)
	if err != nil {
		return nil, err
	}

	certs := make([]*pb.Certificate, len(c.caCerts)+1)
	certs = append(certs, &pb.Certificate{
		Type:     pb.CertificateType_CERTIFICATE_TYPE_X509,
		Encoding: pb.CertificateEncoding_CERTIFICATE_ENCODING_DER,
		Data:     certDer,
	})
	for _, caCert := range c.caCerts {
		certs = append(certs, &pb.Certificate{
			Type:     pb.CertificateType_CERTIFICATE_TYPE_X509,
			Encoding: pb.CertificateEncoding_CERTIFICATE_ENCODING_DER,
			Data:     caCert.Raw,
		})
	}

	return &pb.CertificateChain{
		Certificates: certs,
	}, nil
}
