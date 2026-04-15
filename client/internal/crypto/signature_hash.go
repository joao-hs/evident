package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
)

func ecdsaHashForCurve(key *ecdsa.PublicKey) (crypto.Hash, error) {
	if key == nil || key.Curve == nil {
		return 0, fmt.Errorf("ECDSA public key is nil or has nil curve")
	}

	switch key.Curve {
	case elliptic.P256():
		return crypto.SHA256, nil
	case elliptic.P384():
		return crypto.SHA384, nil
	case elliptic.P521():
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported elliptic curve: %s", key.Curve.Params().Name)
	}
}

func rsaHashForBits(bits int) (crypto.Hash, error) {
	switch bits {
	case 2048:
		return crypto.SHA256, nil
	case 3072:
		return crypto.SHA384, nil
	case 4096:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported RSA key size: %d bits", bits)
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

func hashForPublicKey(publicKey crypto.PublicKey) (crypto.Hash, error) {
	switch key := publicKey.(type) {
	case *ecdsa.PublicKey:
		return ecdsaHashForCurve(key)
	case *rsa.PublicKey:
		return rsaHashForBits(key.Size() * 8)
	default:
		return 0, fmt.Errorf("unsupported public key type: %T", publicKey)
	}
}
