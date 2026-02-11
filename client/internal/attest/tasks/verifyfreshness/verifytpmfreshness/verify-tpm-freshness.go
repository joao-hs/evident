package verifytpmfreshness

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
)

type Input struct {
	TpmEvidence domain.SoftwareEvidence
	Nonce       [64]byte
}

type Output struct{}

func Task(ctx context.Context, input Input) (Output, error) {
	// generated nonce is 64 bytes
	// TPM expects 32 bytes so the evident server behaviour is to use the sha256 of the nonce

	tpmReport := input.TpmEvidence.Report()

	log.Get().Debugln("Verifying freshness of the software evidence by comparing the hashed nonce with the TPM report extra data")
	if len(tpmReport.ExtraData) != 32 {
		return Output{}, fmt.Errorf("invalid TPM report extra data length: expected 32, got %d", len(tpmReport.ExtraData))
	}
	quotedNonce := [32]byte(tpmReport.ExtraData)
	log.Get().Debugf("Quoted nonce from TPM report extra data: %s\n", hex.EncodeToString(quotedNonce[:]))

	originalHashedNonce := sha256.Sum256(input.Nonce[:])
	log.Get().Debugf("Original nonce hashed with sha256: %s\n", hex.EncodeToString(originalHashedNonce[:]))
	if originalHashedNonce != quotedNonce {
		return Output{}, fmt.Errorf("nonce mismatch, software evidence is not fresh")
	}
	log.Get().Debugln("Nonce matches the TPM report extra data, software evidence is fresh")

	return Output{}, nil
}
