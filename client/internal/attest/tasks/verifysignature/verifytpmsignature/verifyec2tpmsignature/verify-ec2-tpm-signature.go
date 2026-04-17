package verifyec2tpmsignature

import (
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/crypto"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
)

type Input struct {
	SwEvidence    domain.SoftwareEvidence
	AkEc          *ecdsa.PublicKey
	AkRsa         *rsa.PublicKey
	OptInstanceID *string
	EkEc          *ecdsa.PublicKey
	ExpectedEkEc  *ecdsa.PublicKey
	EkRsa         *rsa.PublicKey
	ExpectedEkRsa *rsa.PublicKey
}

type Output struct{}

func Task(ctx context.Context, input Input) (Output, error) {
	var (
		err        error
		ok         bool
		zeroOutput Output
	)

	if input.OptInstanceID != nil {
		if input.EkEc == nil && input.EkRsa == nil {
			return zeroOutput, fmt.Errorf("invalid input: instance ID is provided but neither EC nor RSA EK public key is provided")
		}
		if (input.EkEc != nil && input.EkRsa != nil) || (input.EkEc == nil && input.EkRsa == nil) {
			return zeroOutput, fmt.Errorf("invalid input: both EC and RSA EK public keys are provided, but only one should be provided")
		}

		log.Get().Infoln("Verifying the EK matches the AWS provided EK for the instance")
		switch {
		case input.EkEc != nil:
			if !crypto.EqualECDSAPublicKeys(input.EkEc, input.ExpectedEkEc) {
				return zeroOutput, fmt.Errorf("the EK public key fetched from the instance does not match the expected EK public key provided by AWS for the instance")
			}
		case input.EkRsa != nil:
			if !crypto.EqualRSAPublicKeys(input.EkRsa, input.ExpectedEkRsa) {
				return zeroOutput, fmt.Errorf("the EK public key fetched from the instance does not match the expected EK public key provided by AWS for the instance")
			}
		}
	}

	if input.AkEc != nil && input.AkRsa != nil {
		return zeroOutput, fmt.Errorf("invalid input: both EC and RSA AK public keys are provided, but only one should be provided")
	}
	if input.AkEc == nil && input.AkRsa == nil {
		return zeroOutput, fmt.Errorf("invalid input: neither EC nor RSA AK public key is provided, but one must be provided")
	}

	signedRaw := input.SwEvidence.Raw()
	switch {
	case input.AkEc != nil:
		ok, err = crypto.VerifyECDSASignatureWithHashFunc(signedRaw.SignedData(), signedRaw.Signature(), input.AkEc, stdcrypto.SHA256)
	case input.AkRsa != nil:
		ok, err = crypto.VerifyRSASignatureWithHashFunc(signedRaw.SignedData(), signedRaw.Signature(), input.AkRsa, stdcrypto.SHA256)
	}
	if err != nil {
		return zeroOutput, fmt.Errorf("error while verifying the signature of the EC2 TPM quote: %w", err)
	}
	if !ok {
		return zeroOutput, fmt.Errorf("signature verification for EC2 TPM quote failed")
	}

	return Output{}, nil
}
