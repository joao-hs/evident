package getamdtrustedcerts

import (
	"context"
	"crypto/x509"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/trusted/hw/amdkds"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
)

type Input struct {
	Model domain.AMDSEVSNPModel
}

type Output struct {
	Ask *x509.Certificate
	Ark *x509.Certificate
}

func Task(ctx context.Context, input Input) (Output, error) {
	var (
		err        error
		zeroOutput Output
		output     Output
	)

	amdKds := amdkds.GetInstance()

	// TODO: infer model from report

	output.Ask, err = amdKds.GetAsk(input.Model)
	if err != nil {
		return zeroOutput, err
	}

	output.Ark, err = amdKds.GetArk(input.Model)
	if err != nil {
		return zeroOutput, err
	}

	// TODO: get VCEK

	// TODO: check CRL (vcek, ask, ark)

	return output, nil
}
