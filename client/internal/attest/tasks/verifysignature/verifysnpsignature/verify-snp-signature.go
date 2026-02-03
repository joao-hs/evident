package verifysnpsignature

import (
	"context"
	"crypto/x509"
	"fmt"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
)

type Input struct {
	HwEvidence domain.HardwareEvidence[*domain.AmdSevSnpAttestationReport]
	Vcek       *x509.Certificate
	Ask        *x509.Certificate
	Ark        *x509.Certificate
}

type Output struct{}

func Task(ctx context.Context, input Input) (Output, error) {
	var (
		err        error
		zeroOutput Output
	)

	certChain := domain.NewCertChain(input.Vcek)
	if err = certChain.AddParent(input.Ask); err != nil {
		return zeroOutput, err
	}
	if err = certChain.AddParent(input.Ark); err != nil {
		return zeroOutput, err
	}

	signedRaw := input.HwEvidence.Raw()
	signedRaw.SetCertChain(certChain)

	ok, err := signedRaw.IsOk()
	if err != nil {
		return zeroOutput, err
	}
	if !ok {
		return zeroOutput, fmt.Errorf("signature verification for AMD SEV-SNP report failed")
	}

	return zeroOutput, nil
}
