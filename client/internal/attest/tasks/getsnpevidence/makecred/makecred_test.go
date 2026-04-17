package makecred

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// TestRSARoundTrip simulates the full MakeCredential → ActivateCredential flow
// for an RSA EK by manually performing the TPM's decryption steps.
func TestRSARoundTrip(t *testing.T) {
	// Generate a fake EK key pair (we need both sides for the test).
	ekPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ekPub := &ekPriv.PublicKey

	// The credential we want to protect.
	credential := []byte("this-is-a-32-byte-credential!!!!")

	// A fake Name (SHA-256 nameAlg + 32 bytes of hash).
	name := make([]byte, 2+sha256.Size)
	binary.BigEndian.PutUint16(name, 0x000B) // TPM_ALG_SHA256
	rand.Read(name[2:])

	params := Params{
		HashAlg:    crypto.SHA256,
		SymKeyBits: 128,
	}

	// --- MakeCredential ---
	result, err := RSA(ekPub, credential, name, params)
	if err != nil {
		t.Fatal(err)
	}

	// --- Simulate ActivateCredential ---

	// 1. Parse encryptedSecret: TPM2B → RSA-OAEP ciphertext
	secretSize := binary.BigEndian.Uint16(result.EncryptedSecret[:2])
	ciphertext := result.EncryptedSecret[2 : 2+secretSize]

	// 2. RSA-OAEP decrypt to recover the seed.
	seed, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, ekPriv, ciphertext, []byte("IDENTITY\x00"))
	if err != nil {
		t.Fatalf("OAEP decrypt failed: %v", err)
	}

	if len(seed) != sha256.Size {
		t.Fatalf("seed length = %d, want %d", len(seed), sha256.Size)
	}

	// 3. Re-derive keys.
	hmacKey := KDFa(crypto.SHA256, seed, "INTEGRITY", nil, nil, 256)
	encKey := KDFa(crypto.SHA256, seed, "STORAGE", name, nil, 128)

	// 4. Parse credentialBlob: TPM2B_ID_OBJECT → TPM2B(integrityHMAC) || encIdentity
	blobSize := binary.BigEndian.Uint16(result.CredentialBlob[:2])
	inner := result.CredentialBlob[2 : 2+blobSize]

	hmacSize := binary.BigEndian.Uint16(inner[:2])
	integrityHMAC := inner[2 : 2+hmacSize]
	encIdentity := inner[2+hmacSize:]

	// 5. Verify HMAC.
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(encIdentity)
	mac.Write(name)
	expectedMAC := mac.Sum(nil)

	if !hmac.Equal(integrityHMAC, expectedMAC) {
		t.Fatal("integrity HMAC mismatch")
	}

	// 6. Decrypt.
	block, err := aes.NewCipher(encKey)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, aes.BlockSize)
	plaintext := make([]byte, len(encIdentity))
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(plaintext, encIdentity)

	// 7. Unmarshal TPM2B_DIGEST.
	credLen := binary.BigEndian.Uint16(plaintext[:2])
	recovered := plaintext[2 : 2+credLen]

	if string(recovered) != string(credential) {
		t.Fatalf("credential mismatch: got %q, want %q", recovered, credential)
	}
}

// TestECCRoundTrip simulates the full MakeCredential → ActivateCredential flow
// for an ECC EK (P-256).
func TestECCRoundTrip(t *testing.T) {
	// Generate a fake EK key pair.
	ekPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ekPub := &ekPriv.PublicKey

	credential := []byte("another-32byte-credential-here!!")

	name := make([]byte, 2+sha256.Size)
	binary.BigEndian.PutUint16(name, 0x000B)
	rand.Read(name[2:])

	params := Params{
		HashAlg:    crypto.SHA256,
		SymKeyBits: 128,
	}

	// --- MakeCredential ---
	result, err := ECC(ekPub, credential, name, params)
	if err != nil {
		t.Fatal(err)
	}

	// --- Simulate ActivateCredential ---

	// 1. Parse encryptedSecret: TPM2B → TPMS_ECC_POINT(ephemeral pub)
	secretSize := binary.BigEndian.Uint16(result.EncryptedSecret[:2])
	pointBytes := result.EncryptedSecret[2 : 2+secretSize]

	// Parse TPMS_ECC_POINT: TPM2B(x) || TPM2B(y)
	ephXLen := binary.BigEndian.Uint16(pointBytes[:2])
	ephX := pointBytes[2 : 2+ephXLen]
	rest := pointBytes[2+ephXLen:]
	ephYLen := binary.BigEndian.Uint16(rest[:2])
	ephY := rest[2 : 2+ephYLen]

	// Reconstruct ephemeral public key on P-256 and do ECDH with EK private.
	// In Go, we use crypto/ecdh for this.
	coordLen := 32 // P-256
	ephPubUncompressed := make([]byte, 1+2*coordLen)
	ephPubUncompressed[0] = 0x04
	copy(ephPubUncompressed[1+coordLen-len(ephX):1+coordLen], ephX)
	copy(ephPubUncompressed[1+2*coordLen-len(ephY):1+2*coordLen], ephY)

	ecdhEKPriv, err := ekPriv.ECDH()
	if err != nil {
		t.Fatalf("converting EK priv to ECDH: %v", err)
	}

	ephPubKey, err := ecdhEKPriv.Curve().NewPublicKey(ephPubUncompressed)
	if err != nil {
		t.Fatalf("reconstructing ephemeral public: %v", err)
	}

	zBytes, err := ecdhEKPriv.ECDH(ephPubKey)
	if err != nil {
		t.Fatalf("ECDH: %v", err)
	}

	// Derive seed via KDFe.
	ekX := padLeft(ekPub.X.Bytes(), coordLen)
	seed := KDFe(crypto.SHA256, zBytes, "IDENTITY", ephX, ekX, 256)

	// Re-derive keys.
	hmacKey := KDFa(crypto.SHA256, seed, "INTEGRITY", nil, nil, 256)
	encKey := KDFa(crypto.SHA256, seed, "STORAGE", name, nil, 128)

	// Parse credentialBlob.
	blobSize := binary.BigEndian.Uint16(result.CredentialBlob[:2])
	inner := result.CredentialBlob[2 : 2+blobSize]

	hmacSize := binary.BigEndian.Uint16(inner[:2])
	integrityHMAC := inner[2 : 2+hmacSize]
	encIdentity := inner[2+hmacSize:]

	// Verify HMAC.
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(encIdentity)
	mac.Write(name)
	expectedMAC := mac.Sum(nil)

	if !hmac.Equal(integrityHMAC, expectedMAC) {
		t.Fatal("integrity HMAC mismatch")
	}

	// Decrypt.
	block, err := aes.NewCipher(encKey)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, aes.BlockSize)
	plaintext := make([]byte, len(encIdentity))
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(plaintext, encIdentity)

	credLen := binary.BigEndian.Uint16(plaintext[:2])
	recovered := plaintext[2 : 2+credLen]

	if string(recovered) != string(credential) {
		t.Fatalf("credential mismatch: got %q, want %q", recovered, credential)
	}
}

// TestKDFaDeterministic verifies that KDFa produces consistent output for the
// same inputs and that different inputs produce different output.
func TestKDFaDeterministic(t *testing.T) {
	key := []byte("test-key-for-kdf")
	out1 := KDFa(crypto.SHA256, key, "LABEL", []byte("ctx"), nil, 256)
	out2 := KDFa(crypto.SHA256, key, "LABEL", []byte("ctx"), nil, 256)

	if string(out1) != string(out2) {
		t.Fatal("KDFa not deterministic")
	}

	out3 := KDFa(crypto.SHA256, key, "DIFFERENT", []byte("ctx"), nil, 256)
	if string(out1) == string(out3) {
		t.Fatal("KDFa produced same output for different labels")
	}
}

// TestKDFeDeterministic verifies that KDFe produces consistent output.
func TestKDFeDeterministic(t *testing.T) {
	z := []byte("shared-secret-z-value-here-32b!!")
	out1 := KDFe(crypto.SHA256, z, "LABEL", []byte("u"), []byte("v"), 256)
	out2 := KDFe(crypto.SHA256, z, "LABEL", []byte("u"), []byte("v"), 256)

	if string(out1) != string(out2) {
		t.Fatal("KDFe not deterministic")
	}
}

// TestKDFaKDFeDiffer confirms KDFa and KDFe produce different output for the
// same inputs (they use different constructions: HMAC vs plain hash).
func TestKDFaKDFeDiffer(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	a := KDFa(crypto.SHA256, key, "TEST", nil, nil, 256)
	e := KDFe(crypto.SHA256, key, "TEST", nil, nil, 256)
	if string(a) == string(e) {
		t.Fatal("KDFa and KDFe produced identical output — this should be astronomically unlikely")
	}
}

// TestComputeName verifies the Name computation.
func TestComputeName(t *testing.T) {
	pubArea := []byte("fake-marshalled-tpmt-public")
	name := ComputeName(crypto.SHA256, pubArea)

	if len(name) != 2+sha256.Size {
		t.Fatalf("name length = %d, want %d", len(name), 2+sha256.Size)
	}

	algID := binary.BigEndian.Uint16(name[:2])
	if algID != 0x000B {
		t.Fatalf("algID = 0x%04X, want 0x000B", algID)
	}

	h := sha256.Sum256(pubArea)
	if string(name[2:]) != string(h[:]) {
		t.Fatal("name hash mismatch")
	}
}

// TestWrongNameFails verifies that using a different Name during
// "ActivateCredential" causes the HMAC to fail — the core security property.
func TestWrongNameFails(t *testing.T) {
	ekPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	ekPub := &ekPriv.PublicKey

	credential := []byte("secret-credential-data-32bytes!!")

	correctName := make([]byte, 2+sha256.Size)
	binary.BigEndian.PutUint16(correctName, 0x000B)
	rand.Read(correctName[2:])

	params := Params{
		HashAlg:    crypto.SHA256,
		SymKeyBits: 128,
	}
	result, err := RSA(ekPub, credential, correctName, params)
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt seed.
	secretSize := binary.BigEndian.Uint16(result.EncryptedSecret[:2])
	ct := result.EncryptedSecret[2 : 2+secretSize]
	seed, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, ekPriv, ct, []byte("IDENTITY\x00"))

	// Use a WRONG name to derive keys.
	wrongName := make([]byte, 2+sha256.Size)
	binary.BigEndian.PutUint16(wrongName, 0x000B)
	rand.Read(wrongName[2:])

	hmacKey := KDFa(crypto.SHA256, seed, "INTEGRITY", nil, nil, 256)

	blobSize := binary.BigEndian.Uint16(result.CredentialBlob[:2])
	inner := result.CredentialBlob[2 : 2+blobSize]
	hmacSize := binary.BigEndian.Uint16(inner[:2])
	integrityHMAC := inner[2 : 2+hmacSize]
	encIdentity := inner[2+hmacSize:]

	// Recompute HMAC with wrong name — must NOT match.
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(encIdentity)
	mac.Write(wrongName) // wrong!
	if hmac.Equal(integrityHMAC, mac.Sum(nil)) {
		t.Fatal("HMAC matched with wrong Name — this should not happen")
	}
}
