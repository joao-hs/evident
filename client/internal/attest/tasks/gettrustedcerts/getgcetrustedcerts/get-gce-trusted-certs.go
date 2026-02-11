package getgcetrustedcerts

import (
	"context"
	"crypto/x509"
	"encoding/hex"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/trusted/sw/gcekds"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
)

type Input struct {
	AttestationKeyCertificate *x509.Certificate
}

type Output struct {
	IntermediateCACertificate *x509.Certificate
	RootCACertificate         *x509.Certificate
}

func Task(ctx context.Context, input Input) (Output, error) {
	var (
		err        error
		zeroOutput Output
		output     Output
	)

	gceKds := gcekds.GetInstance()

	log.Get().Debugln("Fetching GCE TPM's attestation key (AK) certificate chain from GCE Key Distribution Service (KDS)")
	log.Get().Debugln("Fetching AK's intermediate CA certificate from GCE KDS")
	output.IntermediateCACertificate, err = gceKds.GetIssuerCertificate(input.AttestationKeyCertificate)
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
