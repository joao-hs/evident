// Package makecred implements the TPM2_MakeCredential operation for both
// RSA and ECC endorsement keys.
//
// This package does NOT require a TPM.
package makecred

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
)

// Params configures the MakeCredential operation.
type Params struct {
	// HashAlg is the EK's nameAlg (used for KDF derivations, OAEP, HMAC).
	HashAlg crypto.Hash

	// SymKeyBits is the AES key size in bits for credential encryption.
	// Must match the EK template's symmetric.keyBits (almost always 128).
	SymKeyBits int
}

func Ec2RsaEkParams() Params {
	return Params{
		HashAlg:    crypto.SHA256,
		SymKeyBits: 128,
	}
}

func Ec2EccEkParams() Params {
	return Params{
		HashAlg:    crypto.SHA384,
		SymKeyBits: 256,
	}
}

// Result holds the two output blobs of MakeCredential.
type Result struct {
	// CredentialBlob is the TPM2B_ID_OBJECT: outer size prefix, then
	// TPM2B(integrityHMAC) || encIdentity.
	CredentialBlob []byte

	// EncryptedSecret is the TPM2B_ENCRYPTED_SECRET:
	//   RSA: outer size prefix + RSA-OAEP ciphertext
	//   ECC: outer size prefix + TPMS_ECC_POINT(ephemeral public)
	EncryptedSecret []byte
}

// --------------------------------------------------------------------------
// Public API
// --------------------------------------------------------------------------

// RSA performs MakeCredential with an RSA endorsement key.
//
//   - ekPub:      the EK's RSA public key
//   - credential:  the secret to protect (TPM2B_DIGEST payload, e.g. 32 bytes)
//   - name:        the Name of the key to credential (algID || Hash(TPMT_PUBLIC))
//   - params:      algorithm parameters (use DefaultParams() for standard EK)
func RSA(ekPub *rsa.PublicKey, credential, name []byte, params Params) (*Result, error) {
	if err := validateParams(params); err != nil {
		return nil, err
	}

	hashSize := params.HashAlg.Size()

	// Step 1: Generate random seed (length = hash output size).
	seed := make([]byte, hashSize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, fmt.Errorf("makecred: generating seed: %w", err)
	}

	// Step 2: RSA-OAEP encrypt the seed under the EK public key.
	// Label is the null-terminated ASCII string "IDENTITY\x00".
	oaepLabel := []byte("IDENTITY\x00")
	ciphertext, err := rsa.EncryptOAEP(
		newHashFunc(params.HashAlg)(),
		rand.Reader,
		ekPub,
		seed,
		oaepLabel,
	)
	if err != nil {
		return nil, fmt.Errorf("makecred: RSA-OAEP encrypt: %w", err)
	}
	encryptedSecret := marshalTPM2B(ciphertext)

	// Steps 3-7: derive keys, encrypt, HMAC, assemble.
	credBlob, err := protectCredential(seed, credential, name, params)
	if err != nil {
		return nil, err
	}

	return &Result{
		CredentialBlob:  credBlob,
		EncryptedSecret: encryptedSecret,
	}, nil
}

// ECC performs MakeCredential with an ECC endorsement key (NIST P-256/P-384/P-521).
//
//   - ekPub:      the EK's ECDSA public key
//   - credential:  the secret to protect
//   - name:        the Name of the key to credential
//   - params:      algorithm parameters (use DefaultParams() for standard EK)
func ECC(ekPub *ecdsa.PublicKey, credential, name []byte, params Params) (*Result, error) {
	if err := validateParams(params); err != nil {
		return nil, err
	}

	hashSize := params.HashAlg.Size()

	// Map the ECDSA curve to an ECDH curve.
	ecdhCurve, err := curveToECDH(ekPub.Curve)
	if err != nil {
		return nil, fmt.Errorf("makecred: %w", err)
	}

	// Convert EK public key from *ecdsa.PublicKey to *ecdh.PublicKey.
	ekECDH, err := ecdsaPubToECDH(ekPub)
	if err != nil {
		return nil, fmt.Errorf("makecred: converting EK pub: %w", err)
	}

	// Step 2a: Generate an ephemeral key pair on the same curve.
	ephPriv, err := ecdhCurve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("makecred: generating ephemeral key: %w", err)
	}
	ephPub := ephPriv.PublicKey()

	// Step 2b: ECDH - shared secret is the x-coordinate of the shared point.
	// Go's ecdh returns exactly this for NIST curves.
	zBytes, err := ephPriv.ECDH(ekECDH)
	if err != nil {
		return nil, fmt.Errorf("makecred: ECDH: %w", err)
	}

	// Extract raw x-coordinates for KDFe contextU / contextV.
	coordLen := coordSize(ekPub.Curve)

	ephPubRaw := ephPub.Bytes() // 04 || x || y
	ephX := ephPubRaw[1 : 1+coordLen]
	ephY := ephPubRaw[1+coordLen:]

	ekX := padLeft(ekPub.X.Bytes(), coordLen)

	// Step 2c: Derive seed via KDFe.
	//   KDFe(hashAlg, Z, "IDENTITY", ephemeral.x, EK.x, hashBits)
	seed := KDFe(params.HashAlg, zBytes, "IDENTITY", ephX, ekX, hashSize*8)

	// Marshal the ephemeral public point as TPM2B_ENCRYPTED_SECRET.
	// Inner structure: TPMS_ECC_POINT = TPM2B_ECC_PARAMETER(x) || TPM2B_ECC_PARAMETER(y)
	var pointBuf []byte
	pointBuf = append(pointBuf, marshalTPM2B(ephX)...)
	pointBuf = append(pointBuf, marshalTPM2B(ephY)...)
	encryptedSecret := marshalTPM2B(pointBuf)

	// Steps 3-7: derive keys, encrypt, HMAC, assemble.
	credBlob, err := protectCredential(seed, credential, name, params)
	if err != nil {
		return nil, err
	}

	return &Result{
		CredentialBlob:  credBlob,
		EncryptedSecret: encryptedSecret,
	}, nil
}

// --------------------------------------------------------------------------
// Credential protection (common to RSA and ECC) - Steps 3–7
// --------------------------------------------------------------------------

func protectCredential(seed, credential, name []byte, params Params) ([]byte, error) {
	hashSize := params.HashAlg.Size()
	symKeyBits := params.SymKeyBits

	// Step 3: Derive HMAC key.
	//   KDFa(hashAlg, seed, "INTEGRITY", "", "", hashBits)
	hmacKey := KDFa(params.HashAlg, seed, "INTEGRITY", nil, nil, hashSize*8)

	// Step 4: Derive symmetric encryption key.
	//   KDFa(hashAlg, seed, "STORAGE", Name, "", symKeyBits)
	//   The Name is contextU. This is the binding - a different Name yields
	//   a different key, so ActivateCredential fails for the wrong key.
	encKey := KDFa(params.HashAlg, seed, "STORAGE", name, nil, symKeyBits)

	// Step 5: Encrypt the credential.
	//   Plaintext = marshalled TPM2B_DIGEST: uint16_be(len) || credential bytes
	//   Cipher    = AES-CFB with all-zero IV
	plaintext := marshalTPM2B(credential)

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("makecred: AES cipher: %w", err)
	}
	iv := make([]byte, aes.BlockSize) // 16 zero bytes
	encIdentity := make([]byte, len(plaintext))
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(encIdentity, plaintext)

	// Step 6: Compute integrity HMAC.
	//   HMAC(hmacKey, encIdentity || Name)
	mac := hmac.New(newHashFunc(params.HashAlg), hmacKey)
	mac.Write(encIdentity)
	mac.Write(name)
	integrityHMAC := mac.Sum(nil)

	// Step 7: Assemble the TPM2B_ID_OBJECT (credentialBlob).
	//   inner = TPM2B(integrityHMAC) || encIdentity   (no size prefix on encIdentity)
	//   credentialBlob = TPM2B(inner)
	var inner []byte
	inner = append(inner, marshalTPM2B(integrityHMAC)...)
	inner = append(inner, encIdentity...)

	return marshalTPM2B(inner), nil
}

// --------------------------------------------------------------------------
// KDFa - TPM 2.0 Spec Part 1, Section 11.4.10.2
// --------------------------------------------------------------------------
//
// HMAC-based KDF. Each iteration computes:
//
//	HMAC_hashAlg(key, counter_u32be || label || 0x00 || contextU || contextV || bits_u32be)
//
// counter starts at 1 and increments. Output is concatenated and truncated to
// the requested number of bits.
func KDFa(hashAlg crypto.Hash, key []byte, label string, contextU, contextV []byte, bits int) []byte {
	h := newHashFunc(hashAlg)
	outLen := bits / 8
	result := make([]byte, 0, outLen)

	for counter := uint32(1); len(result) < outLen; counter++ {
		mac := hmac.New(h, key)
		_ = binary.Write(mac, binary.BigEndian, counter)
		mac.Write([]byte(label))
		mac.Write([]byte{0x00}) // null terminator - part of the input, not a separator
		if len(contextU) > 0 {
			mac.Write(contextU)
		}
		if len(contextV) > 0 {
			mac.Write(contextV)
		}
		_ = binary.Write(mac, binary.BigEndian, uint32(bits))
		result = append(result, mac.Sum(nil)...)
	}

	return result[:outLen]
}

// --------------------------------------------------------------------------
// KDFe - TPM 2.0 Spec Part 1, Section 11.4.10.3
// --------------------------------------------------------------------------
//
// Hash-based KDF (NOT HMAC). Each iteration computes:
//
//	Hash_hashAlg(counter_u32be || Z || label || 0x00 || contextU || contextV)
//
// Note: unlike KDFa, there is NO trailing bits field.
func KDFe(hashAlg crypto.Hash, z []byte, label string, contextU, contextV []byte, bits int) []byte {
	h := newHashFunc(hashAlg)
	outLen := bits / 8
	result := make([]byte, 0, outLen)

	for counter := uint32(1); len(result) < outLen; counter++ {
		d := h()
		_ = binary.Write(d, binary.BigEndian, counter)
		d.Write(z)
		d.Write([]byte(label))
		d.Write([]byte{0x00})
		if len(contextU) > 0 {
			d.Write(contextU)
		}
		if len(contextV) > 0 {
			d.Write(contextV)
		}
		// No bits field here - this is the key difference from KDFa.
		result = append(result, d.Sum(nil)...)
	}

	return result[:outLen]
}

// --------------------------------------------------------------------------
// ComputeName computes the TPM Name of a key.
// --------------------------------------------------------------------------
//
// Name = nameAlg_id (2 bytes, big-endian) || Hash_nameAlg(marshalledPublic)
//
// marshalledPublic must be the exact TPMT_PUBLIC binary serialisation that the
// TPM uses (not the TPM2B_PUBLIC - no outer size prefix).
func ComputeName(nameAlg crypto.Hash, marshalledPublic []byte) []byte {
	algID := hashAlgToTPMID(nameAlg)

	h := nameAlg.New()
	h.Write(marshalledPublic)
	digest := h.Sum(nil)

	name := make([]byte, 2+len(digest))
	binary.BigEndian.PutUint16(name, algID)
	copy(name[2:], digest)
	return name
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

func marshalTPM2B(data []byte) []byte {
	buf := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(buf, uint16(len(data)))
	copy(buf[2:], data)
	return buf
}

func newHashFunc(h crypto.Hash) func() hash.Hash {
	switch h {
	case crypto.SHA1:
		// SHA-1 is deprecated but some legacy TPMs use it.
		return crypto.SHA1.New
	case crypto.SHA384:
		return sha512.New384
	case crypto.SHA512:
		return sha512.New
	default:
		return sha256.New
	}
}

func hashAlgToTPMID(h crypto.Hash) uint16 {
	switch h {
	case crypto.SHA1:
		return 0x0004 // TPM_ALG_SHA1
	case crypto.SHA256:
		return 0x000B // TPM_ALG_SHA256
	case crypto.SHA384:
		return 0x000C // TPM_ALG_SHA384
	case crypto.SHA512:
		return 0x000D // TPM_ALG_SHA512
	default:
		return 0x000B
	}
}

func validateParams(p Params) error {
	if !p.HashAlg.Available() {
		return fmt.Errorf("makecred: hash algorithm %v not available", p.HashAlg)
	}
	switch p.SymKeyBits {
	case 128, 192, 256:
		// valid AES key sizes
	default:
		return fmt.Errorf("makecred: unsupported AES key size %d bits", p.SymKeyBits)
	}
	return nil
}

func curveToECDH(c elliptic.Curve) (ecdh.Curve, error) {
	switch c {
	case elliptic.P256():
		return ecdh.P256(), nil
	case elliptic.P384():
		return ecdh.P384(), nil
	case elliptic.P521():
		return ecdh.P521(), nil
	default:
		return nil, errors.New("unsupported elliptic curve")
	}
}

// ecdsaPubToECDH converts an *ecdsa.PublicKey to *ecdh.PublicKey by
// serialising the uncompressed point and re-parsing.
func ecdsaPubToECDH(pub *ecdsa.PublicKey) (*ecdh.PublicKey, error) {
	coordLen := coordSize(pub.Curve)

	buf := make([]byte, 1+2*coordLen)
	buf[0] = 0x04 // uncompressed point prefix
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	// Left-pad coordinates to full length.
	copy(buf[1+coordLen-len(xBytes):1+coordLen], xBytes)
	copy(buf[1+2*coordLen-len(yBytes):1+2*coordLen], yBytes)

	ecdhCurve, err := curveToECDH(pub.Curve)
	if err != nil {
		return nil, err
	}
	return ecdhCurve.NewPublicKey(buf)
}

func coordSize(c elliptic.Curve) int {
	return (c.Params().BitSize + 7) / 8
}

func padLeft(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}
