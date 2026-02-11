package getsnpevidence

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/grpc"
	pb "gitlab.com/dpss-inesc-id/achilles-cvm/client/pb/remote_attestation/v1"
)

type Input struct {
	Client *grpc.Client
}

type Output struct {
	Nonce      [64]byte
	Model      domain.AMDSEVSNPModel
	HwEvidence domain.HardwareEvidence[*domain.AmdSevSnpAttestationReport]
	Vcek       *x509.Certificate
	SwEvidence domain.SoftwareEvidence
	Ak         *x509.Certificate
}

func Task(ctx context.Context, input Input) (Output, error) {
	var (
		zeroOutput Output
		output     Output
	)

	client := input.Client

	nonce := generateRandomBytes()
	output.Nonce = nonce

	req := &pb.GetEvidenceRequest{
		Nonce: nonce[:],
	}

	log.Get().Debugf("Requesting evidence with nonce %s\n", hex.EncodeToString(nonce[:]))
	evidence, err := client.GetEvidence(ctx, req)
	if err != nil {
		return zeroOutput, err
	}
	log.Get().Debugln("Received evidence")

	// TODO: infer model from evidence
	output.Model = domain.AMDSEVSNPModel(domain.ENUM_AMD_SEV_SNP_MODEL_MILAN)

	hardwareEvidence, err := domain.NewAMDSEVSNPHardwareEvidence(output.Model, evidence.Evidence.HardwareEvidence.Raw)
	if err != nil {
		return zeroOutput, err
	}

	output.HwEvidence = hardwareEvidence

	vcekCertBytes := make([]byte, len(evidence.Evidence.HardwareEvidence.Certificate))
	copy(vcekCertBytes, evidence.Evidence.HardwareEvidence.Certificate)

	vcekCert, err := x509.ParseCertificate(vcekCertBytes)
	if err != nil {
		return zeroOutput, err
	}
	output.Vcek = vcekCert

	softwareEvidence, err := domain.NewTPMSoftwareEvidence(domain.CloudServiceProvider(domain.ENUM_CLOUD_SERVICE_PROVIDER_GCP), evidence.Evidence.SoftwareEvidence.SignedRaw, evidence.Evidence.SoftwareEvidence.Signature)
	if err != nil {
		return zeroOutput, err
	}

	output.SwEvidence = softwareEvidence

	akCert, err := x509.ParseCertificate(evidence.Evidence.SoftwareEvidence.Certificate)
	if err != nil {
		return zeroOutput, err
	}

	output.Ak = akCert

	return output, nil
}

// Utils

func generateRandomBytes() [64]byte {
	var b [64]byte
	_, err := rand.Read(b[:])
	if err != nil {
		panic("error while generating random bytes")
	}
	return b
}
