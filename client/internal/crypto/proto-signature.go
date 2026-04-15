package crypto

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
)

// VerifyECDSASignature verifies an ECDSA ASN.1 DER-encoded signature over data.
//
// Hash selection policy:
//   - ECDSA P-256 -> SHA-256
//   - ECDSA P-384 -> SHA-384
//   - ECDSA P-521 -> SHA-512
func VerifyECDSASignature(data []byte, signature []byte, publicKey *ecdsa.PublicKey) (bool, error) {
	if data == nil {
		return false, errors.New("data must not be nil")
	}
	if len(signature) == 0 {
		return false, errors.New("signature must not be empty")
	}
	if publicKey == nil {
		return false, errors.New("public key must not be nil")
	}

	return verifyECDSASignature(data, signature, publicKey)
}

// VerifyRSASignature verifies a PKCS#1 v1.5 signature over data using an RSA public key.
//
// Hash selection policy:
//   - RSA 2048    -> SHA-256
//   - RSA 3072    -> SHA-384
//   - RSA 4096    -> SHA-512
func VerifyRSASignature(data []byte, signature []byte, publicKey *rsa.PublicKey) (bool, error) {
	if data == nil {
		return false, errors.New("data must not be nil")
	}
	if len(signature) == 0 {
		return false, errors.New("signature must not be empty")
	}
	if publicKey == nil {
		return false, errors.New("public key must not be nil")
	}

	return verifyRSASignature(data, signature, publicKey)
}

func verifyECDSASignature(data, signature []byte, key *ecdsa.PublicKey) (bool, error) {
	hashFunc, err := ecdsaHashForCurve(key)
	if err != nil {
		return false, err
	}

	digest, err := hash(data, hashFunc)
	if err != nil {
		return false, err
	}

	return ecdsa.VerifyASN1(key, digest, signature), nil
}

func verifyRSASignature(data, signature []byte, key *rsa.PublicKey) (bool, error) {
	hashFunc, err := rsaHashForBits(key.Size() * 8)
	if err != nil {
		return false, err
	}

	digest, err := hash(data, hashFunc)
	if err != nil {
		return false, err
	}

	err = rsa.VerifyPKCS1v15(key, hashFunc, digest, signature)
	if err != nil {
		if errors.Is(err, rsa.ErrVerification) {
			return false, nil
		}
		return false, fmt.Errorf("RSA verification error: %w", err)
	}

	return true, nil
}
