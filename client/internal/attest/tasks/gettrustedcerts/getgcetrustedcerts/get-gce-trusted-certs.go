package getgcetrustedcerts

import (
	"context"
	"crypto/x509"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/trusted/sw/gcekds"
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

	output.IntermediateCACertificate, err = gceKds.GetIssuerCertificate(input.AttestationKeyCertificate)
	if err != nil {
		return zeroOutput, err
	}

	output.RootCACertificate, err = gceKds.GetIssuerCertificate(output.IntermediateCACertificate)
	if err != nil {
		return zeroOutput, err
	}

	return output, nil
}
