package verifytpmsignature

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
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

	log.Get().Debugln("Verifying TPM quote signature certificate chain")
	certChain := domain.NewCertChain(input.Ak)
	log.Get().Debugf("Attestation Key (AK) certificate, valid as leaf")
	if err = certChain.AddParent(input.IntermediateAkCA); err != nil {
		return zeroOutput, err
	}
	log.Get().Debugf("Intermediate AK CA certificate, valid as AK's parent")
	if err = certChain.AddParent(input.RootAkCA); err != nil {
		return zeroOutput, err
	}
	log.Get().Debugf("Root AK CA certificate, valid as Intermediate AK CA's parent")
	log.Get().Debugln("Certificate chain for TPM quote signature is valid")

	signedRaw := input.SwEvidence.Raw()
	signedRaw.SetCertChain(certChain)

	log.Get().Debugf("Signature: %s", hex.EncodeToString(signedRaw.Signature()))
	log.Get().Debugf("Signed data: %s", hex.EncodeToString(signedRaw.SignedData()))
	log.Get().Debugln("Verifying the signature of the TPM quote")
	ok, err := signedRaw.IsOk()
	if err != nil {
		return zeroOutput, err
	}
	if !ok {
		return zeroOutput, fmt.Errorf("signature verification for TPM quote failed")
	}
	log.Get().Debugln("The TPM quote signature from AK is valid")

	return zeroOutput, nil
}
