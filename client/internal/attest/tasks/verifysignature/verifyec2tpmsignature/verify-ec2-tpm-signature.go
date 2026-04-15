package verifyec2tpmsignature

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/crypto"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
)

type Input struct {
	SwEvidence domain.SoftwareEvidence
	AkEc       *ecdsa.PublicKey
	AkRsa      *rsa.PublicKey
}

type Output struct{}

func Task(ctx context.Context, input Input) (Output, error) {
	var (
		err        error
		ok         bool
		zeroOutput Output
	)

	// EC2 does not offer a certificate chain for the AK.

	if input.AkEc != nil && input.AkRsa != nil {
		return zeroOutput, fmt.Errorf("invalid input: both EC and RSA AK public keys are provided, but only one should be provided")
	}
	if input.AkEc == nil && input.AkRsa == nil {
		return zeroOutput, fmt.Errorf("invalid input: neither EC nor RSA AK public key is provided, but one must be provided")
	}

	signedRaw := input.SwEvidence.Raw()
	switch {
	case input.AkEc != nil:
		ok, err = crypto.VerifyECDSASignature(signedRaw.SignedData(), signedRaw.Signature(), input.AkEc)
	case input.AkRsa != nil:
		ok, err = crypto.VerifyRSASignature(signedRaw.SignedData(), signedRaw.Signature(), input.AkRsa)
	}
	if err != nil {
		return zeroOutput, fmt.Errorf("error while verifying the signature of the EC2 TPM quote: %w", err)
	}
	if !ok {
		return zeroOutput, fmt.Errorf("signature verification for EC2 TPM quote failed")
	}

	return Output{}, nil
}
