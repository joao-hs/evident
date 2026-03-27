package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	pb "gitlab.com/dpss-inesc-id/achilles-cvm/client/pb/evident_protocol/v1"
)

// VerifyDataSignature verifies a signature over data using the provided public key.
// The signature is expected to be in the following format depending on algorithm:
//   - EC:  ASN.1 DER-encoded (r, s) per RFC 3279
//   - RSA: PKCS#1 v1.5 raw signature bytes
func VerifyDataSignature(data []byte, signature []byte, publicKey *pb.PublicKey) (bool, error) {
	// --- Input validation ---
	if data == nil {
		return false, errors.New("data must not be nil")
	}
	if len(signature) == 0 {
		return false, errors.New("signature must not be empty")
	}
	if publicKey == nil {
		return false, errors.New("publicKey must not be nil")
	}
	if len(publicKey.KeyData) == 0 {
		return false, errors.New("publicKey.KeyData must not be empty")
	}

	// --- Validate encoding ---
	if publicKey.Encoding != pb.KeyEncoding_KEY_ENCODING_SPKI_DER {
		return false, fmt.Errorf("unsupported key encoding: %v (only SPKI_DER is supported)", publicKey.Encoding)
	}

	// --- Validate algorithm ---
	switch publicKey.Algorithm {
	case pb.KeyAlgorithm_KEY_ALGORITHM_EC:
	case pb.KeyAlgorithm_KEY_ALGORITHM_RSA:
	default:
		return false, fmt.Errorf("unsupported or unspecified key algorithm: %v", publicKey.Algorithm)
	}

	// --- Parse the public key from SPKI DER ---
	parsedKey, err := x509.ParsePKIXPublicKey(publicKey.KeyData)
	if err != nil {
		return false, fmt.Errorf("failed to parse SPKI DER public key: %w", err)
	}

	// --- Dispatch by algorithm ---
	switch publicKey.Algorithm {
	case pb.KeyAlgorithm_KEY_ALGORITHM_EC:
		return verifyEC(data, signature, parsedKey, publicKey)
	case pb.KeyAlgorithm_KEY_ALGORITHM_RSA:
		return verifyRSA(data, signature, parsedKey, publicKey)
	default:
		// unreachable due to earlier check, but be safe
		return false, fmt.Errorf("unsupported key algorithm: %v", publicKey.Algorithm)
	}
}

// verifyEC handles ECDSA signature verification.
func verifyEC(data []byte, signature []byte, parsedKey any, publicKey *pb.PublicKey) (bool, error) {
	ecKey, ok := parsedKey.(*ecdsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("key algorithm is EC but parsed key type is %T", parsedKey)
	}

	// Validate and extract the declared curve.
	curveParams, ok := publicKey.KeyParams.(*pb.PublicKey_EllipticCurve)
	if !ok || curveParams == nil {
		return false, errors.New("EC key must have elliptic_curve params set")
	}

	expectedCurve, hashFunc, err := ecCurveAndHash(curveParams.EllipticCurve)
	if err != nil {
		return false, err
	}

	// Cross-check: declared curve must match the curve in the actual key material.
	if ecKey.Curve != expectedCurve {
		return false, fmt.Errorf(
			"declared elliptic curve %v does not match curve in key material (%s)",
			curveParams.EllipticCurve, ecKey.Params().Name,
		)
	}

	digest, err := hash(data, hashFunc)
	if err != nil {
		return false, err
	}

	// Expect ASN.1 DER-encoded (r, s).
	r, s, err := parseECDSASignature(signature)
	if err != nil {
		return false, fmt.Errorf("failed to parse ECDSA signature: %w", err)
	}

	valid := ecdsa.Verify(ecKey, digest, r, s)
	return valid, nil
}

// verifyRSA handles RSA PKCS#1 v1.5 signature verification.
func verifyRSA(data []byte, signature []byte, parsedKey any, publicKey *pb.PublicKey) (bool, error) {
	rsaKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("key algorithm is RSA but parsed key type is %T", parsedKey)
	}

	// Validate and extract the declared key size.
	sizeParams, ok := publicKey.KeyParams.(*pb.PublicKey_RsaKeySize)
	if !ok || sizeParams == nil {
		return false, errors.New("RSA key must have rsa_key_size params set")
	}

	expectedBits, err := rsaKeyBits(sizeParams.RsaKeySize)
	if err != nil {
		return false, err
	}

	// Cross-check: declared size must match the actual key size.
	actualBits := rsaKey.N.BitLen()
	if actualBits != expectedBits {
		return false, fmt.Errorf(
			"declared RSA key size %d bits does not match actual key size %d bits",
			expectedBits, actualBits,
		)
	}

	// Hash selection: SHA-256 for 2048, SHA-384 for 3072, SHA-512 for 4096.
	hashFunc, err := rsaHashFunc(sizeParams.RsaKeySize)
	if err != nil {
		return false, err
	}

	digest, err := hash(data, hashFunc)
	if err != nil {
		return false, err
	}

	err = rsa.VerifyPKCS1v15(rsaKey, hashFunc, digest, signature)
	if err != nil {
		if errors.Is(err, rsa.ErrVerification) {
			return false, nil
		}
		return false, fmt.Errorf("RSA verification error: %w", err)
	}
	return true, nil
}

// --- Helpers ---

func ecCurveAndHash(curve pb.EllipticCurve) (elliptic.Curve, crypto.Hash, error) {
	switch curve {
	case pb.EllipticCurve_ELLIPTIC_CURVE_P256:
		return elliptic.P256(), crypto.SHA256, nil
	case pb.EllipticCurve_ELLIPTIC_CURVE_P384:
		return elliptic.P384(), crypto.SHA384, nil
	case pb.EllipticCurve_ELLIPTIC_CURVE_P521:
		return elliptic.P521(), crypto.SHA512, nil
	default:
		return nil, 0, fmt.Errorf("unsupported or unspecified elliptic curve: %v", curve)
	}
}

func rsaKeyBits(size pb.RsaKeySize) (int, error) {
	switch size {
	case pb.RsaKeySize_RSA_KEY_SIZE_2048:
		return 2048, nil
	case pb.RsaKeySize_RSA_KEY_SIZE_3072:
		return 3072, nil
	case pb.RsaKeySize_RSA_KEY_SIZE_4096:
		return 4096, nil
	default:
		return 0, fmt.Errorf("unsupported or unspecified RSA key size: %v", size)
	}
}

func rsaHashFunc(size pb.RsaKeySize) (crypto.Hash, error) {
	switch size {
	case pb.RsaKeySize_RSA_KEY_SIZE_2048:
		return crypto.SHA256, nil
	case pb.RsaKeySize_RSA_KEY_SIZE_3072:
		return crypto.SHA384, nil
	case pb.RsaKeySize_RSA_KEY_SIZE_4096:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported or unspecified RSA key size: %v", size)
	}
}

func hash(data []byte, h crypto.Hash) ([]byte, error) {
	switch h {
	case crypto.SHA256:
		d := sha256.Sum256(data)
		return d[:], nil
	case crypto.SHA384:
		d := sha512.Sum384(data)
		return d[:], nil
	case crypto.SHA512:
		d := sha512.Sum512(data)
		return d[:], nil
	default:
		return nil, fmt.Errorf("unsupported hash function: %v", h)
	}
}

// parseECDSASignature parses an ASN.1 DER-encoded ECDSA signature into (r, s).
func parseECDSASignature(sig []byte) (*big.Int, *big.Int, error) {
	// encoding/asn1 is the standard approach; avoids a third-party dependency.
	var ecSig struct {
		R, S *big.Int
	}
	rest, err := asn1.Unmarshal(sig, &ecSig)
	if err != nil {
		return nil, nil, fmt.Errorf("ASN.1 unmarshal failed: %w", err)
	}
	if len(rest) != 0 {
		return nil, nil, fmt.Errorf("trailing bytes after ASN.1 ECDSA signature (%d bytes)", len(rest))
	}
	if ecSig.R == nil || ecSig.S == nil {
		return nil, nil, errors.New("ECDSA signature has nil r or s component")
	}
	if ecSig.R.Sign() <= 0 || ecSig.S.Sign() <= 0 {
		return nil, nil, errors.New("ECDSA signature r and s must be positive")
	}
	return ecSig.R, ecSig.S, nil
}
