package keyring

//	/srv/evident/trusted-keys/
//	├── entity1.pub.asc
//	├── entity2.pub.asc
//	└── ...
//
// Signature files are expected to be named <KEY_ID>.sig.asc, where KEY_ID may
// be a short (8 hex chars), long (16 hex chars), or full-fingerprint (40 hex
// chars) key identifier.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
)

const trustedKeysDir = "/srv/evident/trusted-keys"

type Result struct {
	// only true if the signature is valid
	isValid bool
	// only true if the signer is in /srv/evident/trusted-keys
	isTrusted bool
	// 16-char fingerprint of the key
	signerFingerprint string
}

func (r Result) IsValid() bool {
	return r.isValid
}

func (r Result) IsTrusted() bool {
	return r.isTrusted
}

func (r Result) SignerFingerprint() string {
	return r.signerFingerprint
}

type TrustedImageDistributorKeyRing interface {
	// More efficient verification if signatureFile name matches the corresponding key ID
	// Tries to verify with all known otherwise
	VerifyDetached(signatureFilePath string, signedFilePath string) (Result, error)
}

type trustedImageDistributorKeyRing struct {
	entities openpgp.EntityList

	isLoaded map[string]bool

	// byKeyID maps uppercase hex strings (short, long, full-fingerprint) to
	// the entity that owns the corresponding key, for O(1) lookup.
	byKeyID map[string]*openpgp.Entity
}

func New() (TrustedImageDistributorKeyRing, error) {
	entries, err := os.ReadDir(trustedKeysDir)
	if err != nil {
		return nil, fmt.Errorf("keyring: read directory %q: %w", trustedKeysDir, err)
	}

	kr := &trustedImageDistributorKeyRing{
		isLoaded: make(map[string]bool),
		byKeyID:  make(map[string]*openpgp.Entity),
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".pub.asc") {
			continue
		}
		path := filepath.Join(trustedKeysDir, entry.Name())
		_, err := kr.loadTrustedKeyFile(path)
		if err != nil {
			log.Get().Warnf("failed to load trusted key, skipping: %s", err.Error())
		}
	}

	if len(kr.entities) == 0 {
		log.Get().Warnf("no trusted keys were loaded, continuing")
	}

	return kr, nil
}

func (kr *trustedImageDistributorKeyRing) VerifyDetached(signatureFilePath string, signedFilePath string) (Result, error) {
	keyID, ok := parseKeyID(filepath.Base(signatureFilePath))
	if !ok {
		return kr.verifyWithCandidates(kr.entities, signatureFilePath, signedFilePath)
	}

	targetEntity, ok := kr.byKeyID[keyID]
	if !ok || targetEntity == nil {
		return kr.verifyWithCandidates(kr.entities, signatureFilePath, signedFilePath)
	}

	singleCandidate := openpgp.EntityList{targetEntity}
	result, err := kr.verifyWithCandidates(singleCandidate, signatureFilePath, signedFilePath)
	if err == nil {
		return result, nil
	}

	return kr.verifyWithCandidates(kr.entities, signatureFilePath, signedFilePath)
}

// --------------------------------------------------------------------------
// Internal helpers
// --------------------------------------------------------------------------

// loadTrustedKeyFile reads one ASCII-armored public key file and registers all entities
// it contains. Returns the count of entities loaded.
func (kr *trustedImageDistributorKeyRing) loadTrustedKeyFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	entities, err := openpgp.ReadArmoredKeyRing(f)
	if err != nil {
		return 0, fmt.Errorf("parse armored key ring: %w", err)
	}
	if len(entities) == 0 {
		return 0, errors.New("file contains no usable OpenPGP keys")
	}

	for _, e := range entities {
		if e == nil {
			continue
		}
		isLoaded, ok := kr.isLoaded[path]
		if ok && isLoaded {
			continue
		}

		kr.entities = append(kr.entities, e)
		kr.indexEntity(e)
		kr.isLoaded[path] = true
	}
	return len(entities), nil
}

// indexEntity populates byKeyID for the primary key and all subkeys of e.
func (kr *trustedImageDistributorKeyRing) indexEntity(e *openpgp.Entity) {
	kr.indexPublicKey(e.PrimaryKey, e)
	for _, sub := range e.Subkeys {
		kr.indexPublicKey(sub.PublicKey, e)
	}
}

func (kr *trustedImageDistributorKeyRing) indexPublicKey(pk *packet.PublicKey, owner *openpgp.Entity) {
	if pk == nil {
		return
	}

	fp := pk.Fingerprint
	if len(fp) == 0 {
		return
	}

	// Full fingerprint.
	kr.byKeyID[fmt.Sprintf("%X", fp)] = owner

	// Long key ID: last 8 bytes of fingerprint.
	if len(fp) >= 8 {
		kr.byKeyID[fmt.Sprintf("%X", fp[len(fp)-8:])] = owner
	}

	// Short key ID: last 4 bytes of fingerprint.
	if len(fp) >= 4 {
		kr.byKeyID[fmt.Sprintf("%X", fp[len(fp)-4:])] = owner
	}
}

func (kr *trustedImageDistributorKeyRing) verifyWithCandidates(candidates openpgp.EntityList, signaturePath string, signedDataPath string) (Result, error) {
	signer, err := checkArmoredDetached(candidates, signaturePath, signedDataPath)
	if err != nil {
		return Result{}, err
	}
	if signer == nil {
		return Result{}, errors.New("signature verified but signer not available")
	}

	result := Result{
		isValid:           true,
		isTrusted:         kr.isTrustedSigner(signer),
		signerFingerprint: longKeyIDFromEntity(signer),
	}
	return result, nil
}

func checkArmoredDetached(candidates openpgp.EntityList, signaturePath string, signedDataPath string) (*openpgp.Entity, error) {
	signatureReader, err := os.Open(signaturePath)
	if err != nil {
		return nil, err
	}
	defer signatureReader.Close()

	signedDataReader, err := os.Open(signedDataPath)
	if err != nil {
		return nil, err
	}
	defer signedDataReader.Close()

	signer, err := openpgp.CheckArmoredDetachedSignature(
		candidates,
		signedDataReader,
		signatureReader,
		nil, // nil uses the library's secure defaults
	)
	if err != nil {
		return nil, err
	}
	return signer, nil
}

func (kr *trustedImageDistributorKeyRing) isTrustedSigner(entity *openpgp.Entity) bool {
	if entity == nil || entity.PrimaryKey == nil {
		return false
	}
	full := fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)
	return kr.byKeyID[full] == entity
}

func longKeyIDFromEntity(entity *openpgp.Entity) string {
	if entity == nil || entity.PrimaryKey == nil {
		return ""
	}
	fp := entity.PrimaryKey.Fingerprint
	if len(fp) < 8 {
		return ""
	}
	return fmt.Sprintf("%X", fp[len(fp)-8:])
}

func parseKeyID(filename string) (string, bool) {
	const suffix = ".sig.asc"
	if !strings.HasSuffix(filename, suffix) {
		return "", false
	}
	id := strings.TrimSuffix(filename, suffix)
	if id == "" {
		return "", false
	}
	// validate that id is hex
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return "", false
		}
	}
	return strings.ToUpper(id), true
}
