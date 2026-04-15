package getgcetrustedcerts

import (
	"context"
	"crypto/x509"
	"fmt"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/trusted/sw/gcekds"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/dotevident"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
)

type Input struct {
	Ak *x509.Certificate
}

type Output struct {
	IntermediateCACertificate *x509.Certificate
	RootCACertificate         *x509.Certificate
	Ak                        *x509.Certificate
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

	log.Get().Debugln("Fetching GCE TPM's attestation key (AK) certificate chain from GCE Key Distribution Service (KDS)")
	log.Get().Debugln("Fetching AK's intermediate CA certificate from GCE KDS")
	output.IntermediateCACertificate, err = gceKds.GetIssuerCertificate(input.Ak)
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

	output.Ak = input.Ak

	return output, nil
}
