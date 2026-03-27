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

type TrustedImageDistributorKeyRing interface {
	// More efficient verification if signatureFile name matches the corresponding key ID
	// Tries to verify with all known otherwise
	VerifyDetached(signatureFilePath string, signedFilePath string) (bool, error)
}

type trustedImageDistributorKeyRing struct {
	entities openpgp.EntityList

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
		byKeyID: make(map[string]*openpgp.Entity),
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

func (kr *trustedImageDistributorKeyRing) VerifyDetached(signatureFilePath string, signedFilePath string) (bool, error) {
	keyID, ok := parseKeyID(filepath.Base(signatureFilePath))
	if !ok {
		return checkArmoredDetached(kr.entities, signatureFilePath, signedFilePath)
	}

	targetEntity, ok := kr.byKeyID[keyID]
	if !ok {
		return checkArmoredDetached(kr.entities, signatureFilePath, signedFilePath)
	}
	if targetEntity == nil {
		return checkArmoredDetached(kr.entities, signatureFilePath, signedFilePath)
	}

	singleCandidate := openpgp.EntityList{targetEntity}
	ok, err := checkArmoredDetached(singleCandidate, signatureFilePath, signedFilePath)
	if ok && err != nil {
		return true, nil
	}

	return checkArmoredDetached(kr.entities, signatureFilePath, signedFilePath)
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
		kr.entities = append(kr.entities, e)
		kr.indexEntity(e)
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

func checkArmoredDetached(candidates openpgp.EntityList, signaturePath string, signedDataPath string) (bool, error) {
	signatureReader, err := os.Open(signaturePath)
	if err != nil {
		return false, err
	}
	defer signatureReader.Close()

	signedDataReader, err := os.Open(signedDataPath)
	if err != nil {
		return false, err
	}
	defer signatureReader.Close()

	_, err = openpgp.CheckArmoredDetachedSignature(
		candidates,
		signedDataReader,
		signatureReader,
		nil, // nil uses the library's secure defaults
	)
	if err != nil {
		return false, err
	}
	return true, nil
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
	return strings.ToUpper(id), true
}
