package getamdtrustedcerts

import (
	"context"
	"crypto/x509"
	"fmt"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/trusted/hw/amdkds"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/dotevident"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
)

type Input struct {
	Model domain.AMDSEVSNPModel
}

type Output struct {
	Ask  *x509.Certificate
	Asvk *x509.Certificate
	Ark  *x509.Certificate
}

func Task(ctx context.Context, input Input) (Output, error) {
	var (
		dot        = dotevident.Get()
		err        error
		path       string
		zeroOutput Output
		output     Output
	)

	amdKds := amdkds.GetInstance()

	log.Get().Debugf("Fetching AMD SEV-SNP certificates from AMD Key Distribution Service (KDS) for model %s", input.Model)
	log.Get().Debugln("Fetching AMD SEV Key (ASK) certificate from AMD KDS")
	output.Ask, err = amdKds.GetAsk(input.Model)
	if err != nil {
		return zeroOutput, err
	}
	path, err = dot.Store(output.Ask.Raw)
	if err != nil {
		return zeroOutput, fmt.Errorf("failed to store ASK certificate: %w", err)
	}
	log.Get().Debugf("Stored ASK certificate with path: %s", path)

	log.Get().Debugln("Fetching AMD SEV VLEK Key (ASVK) certificate from AMD KDS")
	output.Asvk, err = amdKds.GetAsvk(input.Model)
	if err != nil {
		return zeroOutput, err
	}
	path, err = dot.Store(output.Asvk.Raw)
	if err != nil {
		return zeroOutput, fmt.Errorf("failed to store ASVK certificate: %w", err)
	}
	log.Get().Debugf("Stored ASVK certificate with path: %s", path)

	log.Get().Debugln("Fetching AMD Root Key (ARK) certificate from AMD KDS")
	output.Ark, err = amdKds.GetArk(input.Model)
	if err != nil {
		return zeroOutput, err
	}
	path, err = dot.Store(output.Ark.Raw)
	if err != nil {
		return zeroOutput, fmt.Errorf("failed to store ARK certificate: %w", err)
	}
	log.Get().Debugf("Stored ARK certificate with path: %s", path)

	// TODO: get VCEK

	// TODO: check CRL (vcek, ask, ark)

	return output, nil
}
