package getgcetrustedcerts

import (
	"context"
	"crypto/x509"
	"fmt"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/trusted/sw/gcekds"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/dotevident"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
	pb "gitlab.com/dpss-inesc-id/achilles-cvm/client/pb/evident_protocol/v1"
)

type Input struct {
	AkProto *pb.PublicKey
}

type Output struct {
	IntermediateCACertificate *x509.Certificate
	RootCACertificate         *x509.Certificate
	AKCertificate             *x509.Certificate
}

func Task(ctx context.Context, input Input) (Output, error) {
	var (
		dot        = dotevident.Get()
		err        error
		path       string
		zeroOutput Output
		output     Output
	)

	gceKds := gcekds.GetInstance()

	akCertProto := input.AkProto.GetCertificate()
	if akCertProto == nil {
		return zeroOutput, fmt.Errorf("Expected to have GCE TPM's AK certificate, but not found")
	}

	if akCertProto.Type != pb.CertificateType_CERTIFICATE_TYPE_X509 {
		return zeroOutput, fmt.Errorf("Expected GCE TPM's AK certificate to be of type X.509, but got %s", akCertProto.Type.String())
	}

	if len(akCertProto.Data) == 0 {
		return zeroOutput, fmt.Errorf("Expected GCE TPM's AK certificate to be non-empty, but got empty certificate")
	}

	if akCertProto.Encoding != pb.CertificateEncoding_CERTIFICATE_ENCODING_DER {
		// TODO: Support PEM-encoded certificates
		return zeroOutput, fmt.Errorf("Expected GCE TPM's AK certificate to be DER-encoded, but got %s", akCertProto.Encoding.String())
	}

	akCert, err := x509.ParseCertificate(akCertProto.Data)
	if err != nil {
		return zeroOutput, fmt.Errorf("Failed to parse GCE TPM's AK certificate: %w", err)
	}

	output.AKCertificate = akCert

	path, err = dot.Store(output.AKCertificate.Raw)
	if err != nil {
		return zeroOutput, fmt.Errorf("Failed to store GCE TPM's AK certificate: %w", err)
	}
	log.Get().Debugf("Stored GCE TPM's AK certificate with path: %s", path)

	log.Get().Debugln("Fetching GCE TPM's attestation key (AK) certificate chain from GCE Key Distribution Service (KDS)")
	log.Get().Debugln("Fetching AK's intermediate CA certificate from GCE KDS")
	output.IntermediateCACertificate, err = gceKds.GetIssuerCertificate(akCert)
	if err != nil {
		return zeroOutput, err
	}
	path, err = dot.Store(output.IntermediateCACertificate.Raw)
	if err != nil {
		return zeroOutput, fmt.Errorf("Failed to store GCE TPM's AK intermediate CA certificate: %w", err)
	}
	log.Get().Debugf("Stored AK's intermediate CA certificate with path: %s", path)

	log.Get().Debugln("Fetching AK's root CA certificate from GCE KDS")
	output.RootCACertificate, err = gceKds.GetIssuerCertificate(output.IntermediateCACertificate)
	if err != nil {
		return zeroOutput, err
	}
	path, err = dot.Store(output.RootCACertificate.Raw)
	if err != nil {
		return zeroOutput, fmt.Errorf("Failed to store GCE TPM's AK root CA certificate: %w", err)
	}
	log.Get().Debugf("Stored AK's root CA certificate with path: %s", path)

	return output, nil
}
