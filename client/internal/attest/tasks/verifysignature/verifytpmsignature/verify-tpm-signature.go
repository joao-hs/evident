package verifytpmsignature

import (
	"context"
	"crypto/x509"
	"fmt"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
)

type Input struct {
	SwEvidence       domain.SoftwareEvidence
	Ak               *x509.Certificate
	IntermediateAkCA *x509.Certificate
	RootAkCA         *x509.Certificate
}

type Output struct{}

func Task(ctx context.Context, input Input) (Output, error) {
	var (
		err        error
		zeroOutput Output
	)

	certChain := domain.NewCertChain(input.Ak)
	if err = certChain.AddParent(input.IntermediateAkCA); err != nil {
		return zeroOutput, err
	}

	if err = certChain.AddParent(input.RootAkCA); err != nil {
		return zeroOutput, err
	}

	signedRaw := input.SwEvidence.Raw()
	signedRaw.SetCertChain(certChain)

	ok, err := signedRaw.IsOk()
	if err != nil {
		return zeroOutput, err
	}
	if !ok {
		return zeroOutput, fmt.Errorf("signature verification for TPM quote failed")
	}

	return zeroOutput, nil
}
