package verifysnpsignature

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
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

	log.Get().Debugln("Verifying AMD SEV-SNP hardware evidence certificate chain")
	certChain := domain.NewCertChain(input.Vcek)
	log.Get().Debugf("Versioned Chip Endorsement Key (VCEK) certificate, valid as leaf: %s\n", hex.EncodeToString(input.Vcek.Raw))
	if err = certChain.AddParent(input.Ask); err != nil {
		return zeroOutput, err
	}
	log.Get().Debugf("AMD SEV-SNP Attestation Key (ASK) certificate, valid as VCEK's parent: %s\n", hex.EncodeToString(input.Ask.Raw))
	if err = certChain.AddParent(input.Ark); err != nil {
		return zeroOutput, err
	}
	log.Get().Debugf("AMD SEV-SNP AMD Root Key (ARK) certificate, valid as ASK's parent: %s\n", hex.EncodeToString(input.Ark.Raw))
	log.Get().Debugln("Certificate chain for AMD SEV-SNP hardware evidence is valid")

	signedRaw := input.HwEvidence.Raw()
	signedRaw.SetCertChain(certChain)

	log.Get().Debugln("Verifying the signature of the AMD SEV-SNP hardware evidence")
	ok, err := signedRaw.IsOk()
	if err != nil {
		return zeroOutput, err
	}
	if !ok {
		return zeroOutput, fmt.Errorf("signature verification for AMD SEV-SNP report failed")
	}
	log.Get().Debugln("The AMD SEV-SNP hardware evidence signature from VCEK is valid")

	return zeroOutput, nil
}
