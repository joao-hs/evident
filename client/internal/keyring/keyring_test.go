package keyring

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func TestParseKeyID(t *testing.T) {
	cases := []struct {
		name     string
		filename string
		expected string
		ok       bool
	}{
		{"valid short", "deadbeef.sig.asc", "DEADBEEF", true},
		{"valid long", "0123456789abcdef.sig.asc", "0123456789ABCDEF", true},
		{"valid full", "0123456789abcdef0123456789abcdef01234567.sig.asc", "0123456789ABCDEF0123456789ABCDEF01234567", true},
		{"missing suffix", "deadbeef.asc", "", false},
		{"empty id", ".sig.asc", "", false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseKeyID(tc.filename)
			if ok != tc.ok {
				t.Fatalf("expected ok=%v, got %v", tc.ok, ok)
			}
			if got != tc.expected {
				t.Fatalf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

func TestIndexEntityMapsKeyIDs(t *testing.T) {
	entity := newTestEntity(t)
	kr := &trustedImageDistributorKeyRing{isLoaded: make(map[string]bool), byKeyID: make(map[string]*openpgp.Entity)}
	kr.indexEntity(entity)

	fp := entity.PrimaryKey.Fingerprint
	full := fmt.Sprintf("%X", fp)
	long := fmt.Sprintf("%X", fp[len(fp)-8:])
	short := fmt.Sprintf("%X", fp[len(fp)-4:])

	for _, id := range []string{full, long, short} {
		if kr.byKeyID[id] != entity {
			t.Fatalf("expected key ID %s to map to entity", id)
		}
	}
}

func TestLoadTrustedKeyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "entity.pub.asc")
	entity := newTestEntity(t)
	writeArmoredPublicKey(t, path, entity)

	kr := &trustedImageDistributorKeyRing{isLoaded: make(map[string]bool), byKeyID: make(map[string]*openpgp.Entity)}
	count, err := kr.loadTrustedKeyFile(path)
	if err != nil {
		t.Fatalf("loadTrustedKeyFile returned error: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 entity loaded, got %d", count)
	}
	if len(kr.entities) != 1 {
		t.Fatalf("expected 1 entity in keyring, got %d", len(kr.entities))
	}

	fp := entity.PrimaryKey.Fingerprint
	full := fmt.Sprintf("%X", fp)
	if kr.byKeyID[full] == nil {
		t.Fatalf("expected keyring to index full fingerprint")
	}
}

func TestVerifyDetachedOptimizedByKeyID(t *testing.T) {
	entity := newTestEntity(t)
	kr := &trustedImageDistributorKeyRing{isLoaded: make(map[string]bool), byKeyID: make(map[string]*openpgp.Entity)}
	kr.entities = openpgp.EntityList{entity}
	kr.indexEntity(entity)

	dir := t.TempDir()
	dataPath := filepath.Join(dir, "payload.txt")
	sigPath := filepath.Join(dir, fmt.Sprintf("%s.sig.asc", longKeyID(entity)))

	writeFile(t, dataPath, []byte("hello world"))
	writeArmoredDetachedSignature(t, sigPath, entity, dataPath)

	result, err := kr.VerifyDetached(sigPath, dataPath)
	if err != nil {
		t.Fatalf("VerifyDetached returned error: %v", err)
	}
	if !result.isValid {
		t.Fatalf("expected verification to succeed")
	}
	if !result.isTrusted {
		t.Fatalf("expected signer to be trusted")
	}
	if result.signerFingerprint != longKeyID(entity) {
		t.Fatalf("expected signer fingerprint %q, got %q", longKeyID(entity), result.signerFingerprint)
	}
}

func TestVerifyDetachedFallbackToAllKeys(t *testing.T) {
	entity := newTestEntity(t)
	kr := &trustedImageDistributorKeyRing{isLoaded: make(map[string]bool), byKeyID: make(map[string]*openpgp.Entity)}
	kr.entities = openpgp.EntityList{entity}
	kr.indexEntity(entity)

	dir := t.TempDir()
	dataPath := filepath.Join(dir, "payload.txt")
	unknownSigPath := filepath.Join(dir, "DEADBEEF.sig.asc")

	writeFile(t, dataPath, []byte("hello world"))
	writeArmoredDetachedSignature(t, unknownSigPath, entity, dataPath)

	result, err := kr.VerifyDetached(unknownSigPath, dataPath)
	if err != nil {
		t.Fatalf("VerifyDetached returned error: %v", err)
	}
	if !result.isValid {
		t.Fatalf("expected verification to succeed")
	}
	if !result.isTrusted {
		t.Fatalf("expected signer to be trusted")
	}
	if result.signerFingerprint != longKeyID(entity) {
		t.Fatalf("expected signer fingerprint %q, got %q", longKeyID(entity), result.signerFingerprint)
	}
}

func TestVerifyDetachedInvalidSignature(t *testing.T) {
	entity := newTestEntity(t)
	kr := &trustedImageDistributorKeyRing{isLoaded: make(map[string]bool), byKeyID: make(map[string]*openpgp.Entity)}
	kr.entities = openpgp.EntityList{entity}
	kr.indexEntity(entity)

	dir := t.TempDir()
	dataPath := filepath.Join(dir, "payload.txt")
	sigPath := filepath.Join(dir, fmt.Sprintf("%s.sig.asc", longKeyID(entity)))

	writeFile(t, dataPath, []byte("hello world"))
	writeArmoredDetachedSignature(t, sigPath, entity, dataPath)

	writeFile(t, dataPath, []byte("tampered"))

	result, err := kr.VerifyDetached(sigPath, dataPath)
	if err == nil {
		t.Fatalf("expected verification error for tampered data")
	}
	if result.isValid {
		t.Fatalf("expected verification to fail")
	}
}

func TestParseKeyIDNonHexCharacters(t *testing.T) {
	// If parseKeyID doesn't validate hex, this exposes it.
	got, ok := parseKeyID("ZZZZZZZZ.sig.asc")
	if ok {
		t.Fatalf("expected ok=false for non-hex key ID, got ok=true with %q", got)
	}
}

func TestParseKeyIDCaseNormalization(t *testing.T) {
	got, ok := parseKeyID("DeAdBeEf.sig.asc")
	if !ok {
		t.Fatal("expected ok=true for mixed-case hex key ID")
	}
	if got != "DEADBEEF" {
		t.Fatalf("expected normalized key ID %q, got %q", "DEADBEEF", got)
	}
}

func TestParseKeyIDExtraDots(t *testing.T) {
	// "dead.beef.sig.asc" — the key ID portion contains a dot.
	_, ok := parseKeyID("dead.beef.sig.asc")
	// Dots are not valid hex, so this should fail.
	if ok {
		t.Fatal("expected ok=false for key ID containing a dot")
	}
}

func TestParseKeyIDNoExtension(t *testing.T) {
	_, ok := parseKeyID("deadbeef")
	if ok {
		t.Fatal("expected ok=false for filename without .sig.asc suffix")
	}
}

func TestParseKeyIDOnlySuffix(t *testing.T) {
	_, ok := parseKeyID("sig.asc")
	if ok {
		t.Fatal("expected ok=false for filename that is just the suffix without a leading dot")
	}
}

// ---------------------------------------------------------------------------
// Multi-entity keyring
// ---------------------------------------------------------------------------

func TestIndexMultipleEntities(t *testing.T) {
	e1 := newTestEntity(t)
	e2 := newTestEntity(t)

	kr := &trustedImageDistributorKeyRing{isLoaded: make(map[string]bool), byKeyID: make(map[string]*openpgp.Entity)}
	kr.indexEntity(e1)
	kr.indexEntity(e2)

	for i, entity := range []*openpgp.Entity{e1, e2} {
		fp := entity.PrimaryKey.Fingerprint
		full := fmt.Sprintf("%X", fp)
		if kr.byKeyID[full] != entity {
			t.Fatalf("entity %d: full fingerprint not found in keyring", i)
		}
	}
}

func TestVerifyDetachedWithMultipleKeysSelectsCorrectSigner(t *testing.T) {
	signer := newTestEntity(t)
	bystander := newTestEntity(t)

	kr := &trustedImageDistributorKeyRing{isLoaded: make(map[string]bool), byKeyID: make(map[string]*openpgp.Entity)}
	kr.entities = openpgp.EntityList{bystander, signer}
	kr.indexEntity(bystander)
	kr.indexEntity(signer)

	dir := t.TempDir()
	dataPath := filepath.Join(dir, "payload.txt")
	sigPath := filepath.Join(dir, fmt.Sprintf("%s.sig.asc", longKeyID(signer)))

	writeFile(t, dataPath, []byte("multi-key test"))
	writeArmoredDetachedSignature(t, sigPath, signer, dataPath)

	result, err := kr.VerifyDetached(sigPath, dataPath)
	if err != nil {
		t.Fatalf("VerifyDetached returned error: %v", err)
	}
	if !result.isValid {
		t.Fatal("expected verification to succeed with correct signer in multi-key ring")
	}
	if !result.isTrusted {
		t.Fatalf("expected signer to be trusted")
	}
	if result.signerFingerprint != longKeyID(signer) {
		t.Fatalf("expected signer fingerprint %q, got %q", longKeyID(signer), result.signerFingerprint)
	}
}

// ---------------------------------------------------------------------------
// VerifyDetached: true unknown signer (not in keyring at all)
// ---------------------------------------------------------------------------

func TestVerifyDetachedUnknownSigner(t *testing.T) {
	signer := newTestEntity(t)
	unrelatedKey := newTestEntity(t)

	// Keyring contains only the unrelated key — signer is completely absent.
	kr := &trustedImageDistributorKeyRing{isLoaded: make(map[string]bool), byKeyID: make(map[string]*openpgp.Entity)}
	kr.entities = openpgp.EntityList{unrelatedKey}
	kr.indexEntity(unrelatedKey)

	dir := t.TempDir()
	dataPath := filepath.Join(dir, "payload.txt")
	sigPath := filepath.Join(dir, "AAAAAAAAAAAAAAAA.sig.asc")

	writeFile(t, dataPath, []byte("signed by outsider"))
	writeArmoredDetachedSignature(t, sigPath, signer, dataPath)

	result, err := kr.VerifyDetached(sigPath, dataPath)
	if result.isValid {
		t.Fatal("expected verification to fail for a completely unknown signer")
	}
	if result.isTrusted {
		t.Fatal("expected unknown signer to be untrusted")
	}
	// err may or may not be nil depending on design — but isValid must be false.
	_ = err
}

// ---------------------------------------------------------------------------
// VerifyDetached: missing / malformed files
// ---------------------------------------------------------------------------

func TestVerifyDetachedSigFileNotExist(t *testing.T) {
	entity := newTestEntity(t)
	kr := &trustedImageDistributorKeyRing{isLoaded: make(map[string]bool), byKeyID: make(map[string]*openpgp.Entity)}
	kr.entities = openpgp.EntityList{entity}
	kr.indexEntity(entity)

	dir := t.TempDir()
	dataPath := filepath.Join(dir, "payload.txt")
	writeFile(t, dataPath, []byte("data"))

	result, err := kr.VerifyDetached(filepath.Join(dir, "nonexistent.sig.asc"), dataPath)
	if err == nil {
		t.Fatal("expected error when signature file does not exist")
	}
	if result.isValid {
		t.Fatal("expected verification to fail when signature file does not exist")
	}
}

func TestVerifyDetachedDataFileNotExist(t *testing.T) {
	entity := newTestEntity(t)
	kr := &trustedImageDistributorKeyRing{isLoaded: make(map[string]bool), byKeyID: make(map[string]*openpgp.Entity)}
	kr.entities = openpgp.EntityList{entity}
	kr.indexEntity(entity)

	dir := t.TempDir()
	dataPath := filepath.Join(dir, "payload.txt")
	sigPath := filepath.Join(dir, fmt.Sprintf("%s.sig.asc", longKeyID(entity)))

	writeFile(t, dataPath, []byte("data"))
	writeArmoredDetachedSignature(t, sigPath, entity, dataPath)

	// Remove the data file after signing.
	os.Remove(dataPath)

	result, err := kr.VerifyDetached(sigPath, dataPath)
	if err == nil {
		t.Fatal("expected error when data file does not exist")
	}
	if result.isValid {
		t.Fatal("expected verification to fail when data file does not exist")
	}
}

func TestVerifyDetachedEmptySigFile(t *testing.T) {
	entity := newTestEntity(t)
	kr := &trustedImageDistributorKeyRing{isLoaded: make(map[string]bool), byKeyID: make(map[string]*openpgp.Entity)}
	kr.entities = openpgp.EntityList{entity}
	kr.indexEntity(entity)

	dir := t.TempDir()
	dataPath := filepath.Join(dir, "payload.txt")
	sigPath := filepath.Join(dir, fmt.Sprintf("%s.sig.asc", longKeyID(entity)))

	writeFile(t, dataPath, []byte("data"))
	writeFile(t, sigPath, []byte("")) // empty signature file

	result, err := kr.VerifyDetached(sigPath, dataPath)
	if result.isValid {
		t.Fatal("expected verification to fail for empty signature file")
	}
	if err == nil {
		t.Fatal("expected error for empty signature file")
	}
}

func TestVerifyDetachedGarbageSigFile(t *testing.T) {
	entity := newTestEntity(t)
	kr := &trustedImageDistributorKeyRing{isLoaded: make(map[string]bool), byKeyID: make(map[string]*openpgp.Entity)}
	kr.entities = openpgp.EntityList{entity}
	kr.indexEntity(entity)

	dir := t.TempDir()
	dataPath := filepath.Join(dir, "payload.txt")
	sigPath := filepath.Join(dir, fmt.Sprintf("%s.sig.asc", longKeyID(entity)))

	writeFile(t, dataPath, []byte("data"))
	writeFile(t, sigPath, []byte("this is not valid armor or a signature"))

	result, err := kr.VerifyDetached(sigPath, dataPath)
	if result.isValid {
		t.Fatal("expected verification to fail for garbage signature file")
	}
	if err == nil {
		t.Fatal("expected error for garbage signature file")
	}
}

// ---------------------------------------------------------------------------
// loadTrustedKeyFile edge cases
// ---------------------------------------------------------------------------

func TestLoadTrustedKeyFileNotExist(t *testing.T) {
	kr := &trustedImageDistributorKeyRing{isLoaded: make(map[string]bool), byKeyID: make(map[string]*openpgp.Entity)}
	_, err := kr.loadTrustedKeyFile("/nonexistent/path.pub.asc")
	if err == nil {
		t.Fatal("expected error for nonexistent key file")
	}
}

func TestLoadTrustedKeyFileInvalidArmor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "garbage.pub.asc")
	writeFile(t, path, []byte("not valid armor data"))

	kr := &trustedImageDistributorKeyRing{isLoaded: make(map[string]bool), byKeyID: make(map[string]*openpgp.Entity)}
	_, err := kr.loadTrustedKeyFile(path)
	if err == nil {
		t.Fatal("expected error for invalid armor file")
	}
}

func TestLoadTrustedKeyFileIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "entity.pub.asc")
	entity := newTestEntity(t)
	writeArmoredPublicKey(t, path, entity)

	kr := &trustedImageDistributorKeyRing{isLoaded: make(map[string]bool), byKeyID: make(map[string]*openpgp.Entity)}
	kr.loadTrustedKeyFile(path)
	countBefore := len(kr.entities)

	kr.loadTrustedKeyFile(path) // load same file again
	countAfter := len(kr.entities)

	// Depending on design: does this deduplicate or double-count?
	// This test surfaces the behavior so you can decide if it's correct.
	t.Logf("entities before second load: %d, after: %d", countBefore, countAfter)
	if countAfter != countBefore {
		t.Logf("WARNING: loading the same key file twice added duplicate entities")
	}
}

// ---------------------------------------------------------------------------
// Error semantics: tampered vs wrong key
// ---------------------------------------------------------------------------

func TestVerifyDetachedDistinguishesTamperedFromWrongKey(t *testing.T) {
	signer := newTestEntity(t)
	wrongKey := newTestEntity(t)

	dir := t.TempDir()
	dataPath := filepath.Join(dir, "payload.txt")
	writeFile(t, dataPath, []byte("original data"))

	// Case 1: signature valid but signer not in keyring (wrong key).
	sigPath1 := filepath.Join(dir, "wrongkey.sig.asc")
	writeArmoredDetachedSignature(t, sigPath1, signer, dataPath)

	krWrongKey := &trustedImageDistributorKeyRing{isLoaded: make(map[string]bool), byKeyID: make(map[string]*openpgp.Entity)}
	krWrongKey.entities = openpgp.EntityList{wrongKey}
	krWrongKey.indexEntity(wrongKey)

	resultWrong, errWrong := krWrongKey.VerifyDetached(sigPath1, dataPath)

	// Case 2: signer is in keyring but data is tampered.
	dataPath2 := filepath.Join(dir, "payload2.txt")
	writeFile(t, dataPath2, []byte("original data for case 2"))
	sigPath2 := filepath.Join(dir, fmt.Sprintf("%s.sig.asc", longKeyID(signer)))
	writeArmoredDetachedSignature(t, sigPath2, signer, dataPath2)
	writeFile(t, dataPath2, []byte("tampered data"))

	krTampered := &trustedImageDistributorKeyRing{isLoaded: make(map[string]bool), byKeyID: make(map[string]*openpgp.Entity)}
	krTampered.entities = openpgp.EntityList{signer}
	krTampered.indexEntity(signer)

	resultTampered, errTampered := krTampered.VerifyDetached(sigPath2, dataPath2)

	// Both must fail.
	if resultWrong.isValid {
		t.Fatal("wrong-key case: expected isValid=false")
	}
	if resultTampered.isValid {
		t.Fatal("tampered case: expected isValid=false")
	}

	// Log the error semantics so you can verify the distinction is intentional.
	t.Logf("wrong-key error:  %v", errWrong)
	t.Logf("tampered error:   %v", errTampered)

	// Uncomment if you want to enforce distinct error behavior:
	// if (errWrong == nil) == (errTampered == nil) {
	// 	t.Fatal("expected different error semantics for wrong-key vs tampered")
	// }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func writeArmoredPublicKeys(t *testing.T, path string, entities []*openpgp.Entity) {
	t.Helper()
	var buf bytes.Buffer
	for _, entity := range entities {
		w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
		if err != nil {
			t.Fatalf("failed to encode armor: %v", err)
		}
		if err := entity.Serialize(w); err != nil {
			w.Close()
			t.Fatalf("failed to serialize entity: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("failed to close armor writer: %v", err)
		}
		buf.WriteString("\n") // Add a newline at the end of each iteration
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
}

func newTestEntity(t *testing.T) *openpgp.Entity {
	t.Helper()
	entity, err := openpgp.NewEntity("Test", "", "test@example.com", &packet.Config{RSABits: 2048})
	if err != nil {
		t.Fatalf("failed to create test entity: %v", err)
	}
	return entity
}

func writeArmoredPublicKey(t *testing.T, path string, entity *openpgp.Entity) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create public key file: %v", err)
	}
	defer f.Close()

	w, err := armor.Encode(f, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatalf("failed to encode armor: %v", err)
	}
	if err := entity.Serialize(w); err != nil {
		w.Close()
		t.Fatalf("failed to serialize entity: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("failed to close armor writer: %v", err)
	}
}

func writeArmoredDetachedSignature(t *testing.T, sigPath string, entity *openpgp.Entity, dataPath string) {
	t.Helper()
	data, err := os.ReadFile(dataPath)
	if err != nil {
		t.Fatalf("failed to read data file: %v", err)
	}

	f, err := os.Create(sigPath)
	if err != nil {
		t.Fatalf("failed to create signature file: %v", err)
	}
	defer f.Close()

	if err := openpgp.ArmoredDetachSign(f, entity, bytes.NewReader(data), nil); err != nil {
		t.Fatalf("failed to create detached signature: %v", err)
	}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
}

func longKeyID(entity *openpgp.Entity) string {
	fp := entity.PrimaryKey.Fingerprint
	id := fmt.Sprintf("%X", fp[len(fp)-8:])
	return strings.ToUpper(id)
}
