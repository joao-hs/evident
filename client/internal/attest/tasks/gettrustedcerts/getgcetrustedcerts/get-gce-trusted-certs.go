package getgcetrustedcerts

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/trusted/sw/gcekds"
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
		err        error
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

	log.Get().Debugln("Fetching GCE TPM's attestation key (AK) certificate chain from GCE Key Distribution Service (KDS)")
	log.Get().Debugln("Fetching AK's intermediate CA certificate from GCE KDS")
	output.IntermediateCACertificate, err = gceKds.GetIssuerCertificate(akCert)
	if err != nil {
		return zeroOutput, err
	}
	log.Get().Debugf("Received AK's intermediate CA certificate from GCE KDS: %s\n", hex.EncodeToString(output.IntermediateCACertificate.Raw))

	log.Get().Debugln("Fetching AK's root CA certificate from GCE KDS")
	output.RootCACertificate, err = gceKds.GetIssuerCertificate(output.IntermediateCACertificate)
	if err != nil {
		return zeroOutput, err
	}
	log.Get().Debugf("Received AK's root CA certificate from GCE KDS: %s\n", hex.EncodeToString(output.RootCACertificate.Raw))

	return output, nil
}
