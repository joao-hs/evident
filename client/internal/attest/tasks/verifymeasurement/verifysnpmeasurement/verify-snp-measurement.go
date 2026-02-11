package verifysnpmeasurement

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/virtee/sev-snp-measure-go/guest"
	"github.com/virtee/sev-snp-measure-go/ovmf"
	"github.com/virtee/sev-snp-measure-go/vmmtypes"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
)

type Input struct {
	SnpEvidence     domain.HardwareEvidence[*domain.AmdSevSnpAttestationReport]
	OvmfBinaryBytes []byte
	CPUCount        int
}

type Output struct{}

func Task(ctx context.Context, input Input) (Output, error) {
	var (
		zeroOutput Output
	)

	if len(input.OvmfBinaryBytes) == 0 {
		return zeroOutput, fmt.Errorf("OVMF binary is empty")
	}

	tmpFd, err := os.CreateTemp("", "ovmf-*.bin")
	if err != nil {
		return zeroOutput, err
	}
	defer os.Remove(tmpFd.Name())
	defer tmpFd.Close()

	if _, err := tmpFd.Write(input.OvmfBinaryBytes); err != nil {
		return zeroOutput, err
	}

	ovmf, err := ovmf.New(tmpFd.Name())
	if err != nil {
		return zeroOutput, err
	}

	log.Get().Debugln("Verifying the measurement from the SNP attestation report matches the expected measurement derived from the given UEFI binary")
	log.Get().Debugln("Deriving the expected measurement from the given UEFI binary")
	ovmfHash, err := guest.OVMFHash(ovmf)
	if err != nil {
		return zeroOutput, err
	}

	ld, err := guest.LaunchDigestFromOVMF(
		ovmf,
		0x1, // default guest features
		input.CPUCount,
		ovmfHash,
		vmmtypes.GCE,
		"EPYC-Milan-v2", // vCPU signature does not influence launch digest
	)
	if err != nil {
		return zeroOutput, err
	}
	log.Get().Debugf("Expected measurement derived from the UEFI binary: %s\n", hex.EncodeToString(ld[:]))

	report := input.SnpEvidence.Report()
	if report == nil {
		return zeroOutput, fmt.Errorf("SNP attestation report is nil")
	}
	log.Get().Debugf("Measurement from SNP attestation report: %s\n", hex.EncodeToString(report.Measurement[:]))
	if !bytes.Equal(ld[:], report.Measurement[:]) {
		return zeroOutput, fmt.Errorf("measurement does not match")
	}
	log.Get().Debugln("Measurement from SNP attestation report matches the expected measurement derived from the UEFI binary")

	return zeroOutput, nil
}
