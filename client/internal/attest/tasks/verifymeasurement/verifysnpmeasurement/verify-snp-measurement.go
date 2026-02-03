package verifysnpmeasurement

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/virtee/sev-snp-measure-go/guest"
	"github.com/virtee/sev-snp-measure-go/ovmf"
	"github.com/virtee/sev-snp-measure-go/vmmtypes"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
)

type Input struct {
	SnpEvidence     domain.HardwareEvidence[*domain.AmdSevSnpAttestationReport]
	OvmfBinaryBytes []byte
	CPUCount        uint32
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

	ovmfHash, err := guest.OVMFHash(ovmf)
	if err != nil {
		return zeroOutput, err
	}

	ld, err := guest.LaunchDigestFromOVMF(
		ovmf,
		0x1, // default guest features
		int(input.CPUCount),
		ovmfHash,
		vmmtypes.GCE,
		"EPYC-Milan-v2", // vCPU signature does not influence launch digest
	)
	if err != nil {
		return zeroOutput, err
	}

	report := input.SnpEvidence.Report()
	if report == nil {
		return zeroOutput, fmt.Errorf("SNP attestation report is nil")
	}
	if !bytes.Equal(ld[:], report.Measurement[:]) {
		return zeroOutput, fmt.Errorf("measurement does not match")
	}

	return zeroOutput, nil
}
