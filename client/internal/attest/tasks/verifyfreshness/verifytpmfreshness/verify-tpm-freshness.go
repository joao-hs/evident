package verifytpmfreshness

import (
	"context"
	"crypto/sha256"
	"fmt"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
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

	if len(tpmReport.ExtraData) != 32 {
		return Output{}, fmt.Errorf("invalid TPM report extra data length: expected 32, got %d", len(tpmReport.ExtraData))
	}
	quotedNonce := [32]byte(tpmReport.ExtraData)

	originalHashedNonce := sha256.Sum256(input.Nonce[:])
	if originalHashedNonce != quotedNonce {
		return Output{}, fmt.Errorf("nonce mismatch, software evidence is not fresh")
	}

	return Output{}, nil
}
