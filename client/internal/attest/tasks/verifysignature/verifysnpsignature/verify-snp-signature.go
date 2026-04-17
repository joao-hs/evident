package verifysnpsignature

import (
	"context"
	"crypto/x509"
	"fmt"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
)

type Input struct {
	HwEvidence domain.HardwareEvidence[*domain.AmdSevSnpAttestationReport]
	// At most one of VCEK or VLEK can be provided
	Vcek *x509.Certificate
	// At most one of VCEK or VLEK can be provided
	Vlek *x509.Certificate
	// At most one of ASK or ASVK can be provided
	Ask *x509.Certificate
	// At most one of ASK or ASVK can be provided
	Asvk *x509.Certificate
	Ark  *x509.Certificate
}

type Output struct{}

func Task(ctx context.Context, input Input) (Output, error) {
	var (
		err        error
		zeroOutput Output
	)

	if (input.Vcek != nil && input.Vlek != nil) || (input.Vcek == nil && input.Vlek == nil) {
		return zeroOutput, fmt.Errorf("invalid input: either VCEK or VLEK must be provided, but not both")
	}
	if (input.Ask != nil && input.Asvk != nil) || (input.Ask == nil && input.Asvk == nil) {
		return zeroOutput, fmt.Errorf("invalid input: either ASK or ASVK must be provided, but not both")
	}

	log.Get().Debugln("Verifying AMD SEV-SNP hardware evidence certificate chain")

	var certChain *domain.CertChain
	switch {
	case input.Vcek != nil:
		log.Get().Debugf("Versioned Chip Endorsement Key (VCEK) certificate, valid as leaf")
		certChain = domain.NewCertChain(input.Vcek)
		if err = certChain.AddParent(input.Ask); err != nil {
			return zeroOutput, err
		}
		log.Get().Debugf("AMD SEV-SNP Attestation Key (ASK) certificate, valid as VCEK's parent")
	case input.Vlek != nil:
		log.Get().Debugf("Versioned Loaded Endorsement Key (VLEK) certificate, valid as leaf")
		certChain = domain.NewCertChain(input.Vlek)
		if err = certChain.AddParent(input.Asvk); err != nil {
			return zeroOutput, err
		}
		log.Get().Debugf("AMD SEV-SNP VLEK Signing Key (ASVK) certificate, valid as VLEK's parent")
	}

	if err = certChain.AddParent(input.Ark); err != nil {
		return zeroOutput, err
	}
	log.Get().Debugf("AMD SEV-SNP AMD Root Key (ARK) certificate, valid as ASK/ASVK's parent")
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
	log.Get().Debugln("The AMD SEV-SNP hardware evidence signature from VCEK/VLEK is valid")

	return zeroOutput, nil
}
