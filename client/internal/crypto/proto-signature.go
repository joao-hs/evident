package crypto

import (
	"crypto"
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

	hashFunc, err := ecdsaHashForCurve(publicKey)
	if err != nil {
		return false, err
	}

	return verifyECDSASignature(data, signature, publicKey, hashFunc)
}

// VerifyECDSASignatureWithHashFunc verifies an ECDSA ASN.1 DER-encoded signature over data using the specified hash function.
func VerifyECDSASignatureWithHashFunc(data []byte, signature []byte, publicKey *ecdsa.PublicKey, hashFunc crypto.Hash) (bool, error) {
	if data == nil {
		return false, errors.New("data must not be nil")
	}
	if len(signature) == 0 {
		return false, errors.New("signature must not be empty")
	}
	if publicKey == nil {
		return false, errors.New("public key must not be nil")
	}
	if !hashFunc.Available() {
		return false, fmt.Errorf("hash function %v is not available", hashFunc)
	}

	return verifyECDSASignature(data, signature, publicKey, hashFunc)
}

// VerifyRSASignature verifies a PKCS#1 v1.5 signature over data using an RSA public key.
//
// Hash selection policy:
//   - RSA 2048 -> SHA-256
//   - RSA 3072 -> SHA-384
//   - RSA 4096 -> SHA-512
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

	hashFunc, err := rsaHashForBits(publicKey.Size() * 8)
	if err != nil {
		return false, err
	}

	return verifyRSASignature(data, signature, publicKey, hashFunc)
}

// VerifyRSASignatureWithHashFunc verifies a PKCS#1 v1.5 signature over data using an RSA public key and the specified hash function.
func VerifyRSASignatureWithHashFunc(data []byte, signature []byte, publicKey *rsa.PublicKey, hashFunc crypto.Hash) (bool, error) {
	if data == nil {
		return false, errors.New("data must not be nil")
	}
	if len(signature) == 0 {
		return false, errors.New("signature must not be empty")
	}
	if publicKey == nil {
		return false, errors.New("public key must not be nil")
	}
	if !hashFunc.Available() {
		return false, fmt.Errorf("hash function %v is not available", hashFunc)
	}

	return verifyRSASignature(data, signature, publicKey, hashFunc)
}

func verifyECDSASignature(data, signature []byte, key *ecdsa.PublicKey, hashFunc crypto.Hash) (bool, error) {
	digest, err := hash(data, hashFunc)
	if err != nil {
		return false, err
	}

	return ecdsa.VerifyASN1(key, digest, signature), nil
}

func verifyRSASignature(data, signature []byte, key *rsa.PublicKey, hashFunc crypto.Hash) (bool, error) {
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
