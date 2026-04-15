package verifytpmfreshness

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
)

type Input struct {
	TpmEvidence  domain.SoftwareEvidence
	Nonce        [64]byte
	InstanceCert *x509.Certificate
	Secret       []byte
}

type Output struct{}

func Task(ctx context.Context, input Input) (Output, error) {
	var err error
	// generated nonce is 64 bytes
	// TPM expects 32 bytes so the evident server behaviour is to use the sha256 of the nonce

	tpmReport := input.TpmEvidence.Report()

	log.Get().Debugln("Verifying freshness of the software evidence by comparing the hashed nonce with the TPM report extra data")
	if len(tpmReport.ExtraData) != 32 {
		return Output{}, fmt.Errorf("invalid TPM report extra data length: expected 32, got %d", len(tpmReport.ExtraData))
	}
	quotedNonce := [32]byte(tpmReport.ExtraData)
	log.Get().Debugf("Quoted qualifying data: %s", hex.EncodeToString(quotedNonce[:]))

	var instanceKeySPKIBytes []byte
	switch input.InstanceCert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		pubKey := input.InstanceCert.PublicKey.(*ecdsa.PublicKey)
		instanceKeySPKIBytes, err = x509.MarshalPKIXPublicKey(pubKey)
	case *rsa.PublicKey:
		pubKey := input.InstanceCert.PublicKey.(*rsa.PublicKey)
		instanceKeySPKIBytes, err = x509.MarshalPKIXPublicKey(pubKey)
	default:
		return Output{}, fmt.Errorf("unsupported instance key public key type: %T", input.InstanceCert.PublicKey)
	}
	if err != nil {
		return Output{}, fmt.Errorf("failed to marshal instance key public key: %w", err)
	}

	buffer := bytes.Buffer{}
	buffer.Write(input.Nonce[:])
	buffer.Write(instanceKeySPKIBytes)
	if input.Secret != nil {
		buffer.Write(input.Secret)
	}

	qualifyingData := sha256.Sum256(buffer.Bytes())
	log.Get().Debugf("Expected quoted qualifying data: %s", hex.EncodeToString(qualifyingData[:]))
	if qualifyingData != quotedNonce {
		return Output{}, fmt.Errorf("nonce mismatch, software evidence is not fresh")
	}
	log.Get().Debugln("Nonce matches the TPM report extra data, software evidence is fresh")

	return Output{}, nil
}
