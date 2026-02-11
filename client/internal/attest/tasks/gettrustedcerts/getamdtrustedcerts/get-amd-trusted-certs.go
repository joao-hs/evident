package getamdtrustedcerts

import (
	"context"
	"crypto/x509"
	"encoding/hex"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/trusted/hw/amdkds"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
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

	log.Get().Debugf("Fetching AMD SEV-SNP certificates from AMD Key Distribution Service (KDS) for model %s\n", input.Model)
	log.Get().Debugln("Fetching AMD SEV Key (ASK) certificate from AMD KDS")
	output.Ask, err = amdKds.GetAsk(input.Model)
	if err != nil {
		return zeroOutput, err
	}
	log.Get().Debugf("Received ASK certificate from AMD KDS: %s\n", hex.EncodeToString(output.Ask.Raw))

	log.Get().Debugln("Fetching AMD Root Key (ARK) certificate from AMD KDS")
	output.Ark, err = amdKds.GetArk(input.Model)
	if err != nil {
		return zeroOutput, err
	}
	log.Get().Debugf("Received ARK certificate from AMD KDS: %s\n", hex.EncodeToString(output.Ark.Raw))

	// TODO: get VCEK

	// TODO: check CRL (vcek, ask, ark)

	return output, nil
}
