package verifysnpfreshness

import (
	"bytes"
	"context"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
	pb "gitlab.com/dpss-inesc-id/achilles-cvm/client/pb/evident_protocol/v1"
)

type Input struct {
	SnpEvidence domain.HardwareEvidence[*domain.AmdSevSnpAttestationReport]
	Nonce       [64]byte
	InstanceKey *pb.PublicKey
	Ak          *x509.Certificate
}

type Output struct{}

func Task(ctx context.Context, input Input) (Output, error) {
	report := input.SnpEvidence.Report()
	if report == nil {
		return Output{}, fmt.Errorf("SNP attestation report is nil")
	}

	log.Get().Debugln("Verifying freshness and artifact binding of the hardware evidence")
	log.Get().Debugf("Data: SHA512(%x||%x||%x)", input.Nonce[:], input.InstanceKey.KeyData, input.Ak.Raw)
	buffer := bytes.Buffer{}
	buffer.Write(input.Nonce[:])
	buffer.Write(input.InstanceKey.KeyData)
	buffer.Write(input.Ak.Raw)
	digest := sha512.Sum512(buffer.Bytes())

	log.Get().Debugf("Computed digest: %s\n", hex.EncodeToString(digest[:]))
	log.Get().Debugf("Report data from the hardware evidence: %s\n", hex.EncodeToString(report.ReportData[:]))

	if digest != report.ReportData {
		return Output{}, fmt.Errorf("nonce mismatch, hardware evidence is not fresh")
	}
	log.Get().Debugln("Nonce matches the report data, hardware evidence is fresh")

	return Output{}, nil
}
