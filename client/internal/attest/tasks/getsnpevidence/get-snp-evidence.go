package getsnpevidence

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/crypto"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/grpc"
	pb "gitlab.com/dpss-inesc-id/achilles-cvm/client/pb/evident_protocol/v1"
	"google.golang.org/protobuf/proto"
)

type Input struct {
	Client                     *grpc.Client
	AdditionalArtificatsBundle *pb.AdditionalArtifactsBundle
}

type Output struct {
	InstanceKey *pb.PublicKey
	Nonce       [64]byte
	Model       domain.AMDSEVSNPModel
	HwEvidence  domain.HardwareEvidence[*domain.AmdSevSnpAttestationReport]
	Vcek        *x509.Certificate
	SwEvidence  domain.SoftwareEvidence
	AkProto     *pb.PublicKey
}

func Task(ctx context.Context, input Input) (Output, error) {
	var (
		zeroOutput Output
		output     Output
	)

	client := input.Client

	var additionalArtifactsBundle = input.AdditionalArtificatsBundle
	if additionalArtifactsBundle == nil {
		log.Get().Debugln("Requesting additional artifacts")
		resp, err := client.GetAdditionalArtifacts(ctx, &pb.GetAdditionalArtifactsRequest{})
		if err != nil {
			return zeroOutput, err
		}
		log.Get().Debugln("Received additional artifacts")

		if resp == nil {
			return zeroOutput, fmt.Errorf("received nil response for additional artifacts")
		}

		// We do not have prior knowledge of the expected instance key; for now, we just verify the signature's validity
		ok, err := crypto.VerifyDataSignature(resp.SerializedAdditionalArtifactsBundle, resp.Signature, resp.SigningKey)
		if err != nil {
			return zeroOutput, err
		}
		if !ok {
			return zeroOutput, fmt.Errorf("invalid signature for additional artifacts bundle")
		}

		additionalArtifactsBundle = &pb.AdditionalArtifactsBundle{}
		err = proto.Unmarshal(resp.SerializedAdditionalArtifactsBundle, additionalArtifactsBundle)
		if err != nil {
			return zeroOutput, err
		}
	}
	// This task needs {InstanceKey} from the AdditionalArtifactsBundle;
	instanceKey := additionalArtifactsBundle.InstanceKey
	if instanceKey == nil {
		return zeroOutput, fmt.Errorf("instance key is missing in the additional artifacts bundle")
	}
	output.InstanceKey = instanceKey

	// TODO: (maybe) check if instanceKey matches signingkey from SignedAdditionalArtifactsBundle

	nonce := generateRandomBytes()
	output.Nonce = nonce

	req := &pb.GetEvidenceRequest{
		Nonce: nonce[:],
	}

	log.Get().Debugf("Requesting evidence with nonce %s\n", hex.EncodeToString(nonce[:]))
	signedEvidenceBundle, err := client.GetEvidence(ctx, req)
	if err != nil {
		return zeroOutput, err
	}
	log.Get().Debugln("Received evidence")

	evidenceBundleBytes := signedEvidenceBundle.SerializedEvidenceBundle
	signature := signedEvidenceBundle.Signature
	signingKey := signedEvidenceBundle.SigningKey

	if signingKey == nil {
		return zeroOutput, fmt.Errorf("signing key is missing in the response")
	}

	if !crypto.EqualPublicKeys(signingKey, instanceKey) {
		return zeroOutput, fmt.Errorf("signing key in the response does not match the expected instance key")
	}

	log.Get().Debugf("Signature: %s", hex.EncodeToString(signature))

	isValid, err := crypto.VerifyDataSignature(evidenceBundleBytes, signature, instanceKey)
	if err != nil {
		return zeroOutput, err
	}
	if !isValid {
		return zeroOutput, fmt.Errorf("invalid signature for evidence bundle")
	}

	var evidence pb.EvidenceBundle
	err = proto.Unmarshal(evidenceBundleBytes, &evidence)
	if err != nil {
		return zeroOutput, err
	}

	hardwareEvidenceWrapper, ok := evidence.HardwareEvidence.(*pb.EvidenceBundle_SnpEvidence)
	if !ok || hardwareEvidenceWrapper == nil {
		return zeroOutput, fmt.Errorf("hardware evidence is not of type SNP")
	}
	snpEvidenceProto := hardwareEvidenceWrapper.SnpEvidence

	// TODO: infer model from evidence
	output.Model = domain.AMDSEVSNPModel(domain.ENUM_AMD_SEV_SNP_MODEL_MILAN)

	snpEvidence, err := domain.NewAMDSEVSNPHardwareEvidence(output.Model, snpEvidenceProto)
	if err != nil {
		return zeroOutput, err
	}

	output.HwEvidence = snpEvidence

	// TODO: better check for expected public key before parsing the certificate

	vcekCertProto := snpEvidenceProto.SigningKey.GetCertificate()
	if vcekCertProto == nil {
		return zeroOutput, fmt.Errorf("vcek certificate is missing")
	}

	vcekCertBytes := make([]byte, len(snpEvidenceProto.SigningKey.Certificate.Data))
	copy(vcekCertBytes, snpEvidenceProto.SigningKey.Certificate.Data)

	vcekCert, err := x509.ParseCertificate(vcekCertBytes)
	if err != nil {
		return zeroOutput, err
	}
	output.Vcek = vcekCert

	softwareEvidenceWrapper, ok := evidence.SoftwareEvidence.(*pb.EvidenceBundle_TpmEvidence)
	if !ok || softwareEvidenceWrapper == nil {
		return zeroOutput, fmt.Errorf("software evidence is not of type TPM")
	}

	tpmEvidenceProto := softwareEvidenceWrapper.TpmEvidence

	tpmEvidence, err := domain.NewTPMSoftwareEvidence(domain.CloudServiceProvider(domain.ENUM_CLOUD_SERVICE_PROVIDER_GCP), tpmEvidenceProto.SignedRaw, tpmEvidenceProto.Signature)
	if err != nil {
		return zeroOutput, err
	}

	output.SwEvidence = tpmEvidence

	if tpmEvidenceProto.SigningKey == nil {
		return zeroOutput, fmt.Errorf("AK public key for TPM evidence is missing")
	}

	output.AkProto = tpmEvidenceProto.SigningKey

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
