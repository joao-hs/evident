package getsnpevidence

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"fmt"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/crypto"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/dotevident"
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
		dot        = dotevident.Get()
		path       string
		zeroOutput Output
		output     Output
		err        error
	)

	client := input.Client

	var additionalArtifactsBundle = input.AdditionalArtificatsBundle
	if additionalArtifactsBundle == nil {
		log.Get().Debugln("Requesting additional artifacts")
		resp, err := client.GetAdditionalArtifacts(ctx, &pb.GetAdditionalArtifactsRequest{})
		if err != nil {
			return zeroOutput, err
		}
		if resp == nil {
			return zeroOutput, fmt.Errorf("received nil response for additional artifacts")
		}

		ok, err := crypto.IsValidPublicKey(resp.SigningKey)
		if err != nil {
			return zeroOutput, fmt.Errorf("error while validating signing key in additional artifacts response: %w", err)
		}
		if !ok {
			return zeroOutput, fmt.Errorf("invalid signing key in additional artifacts response")
		}

		path, err = dot.StoreGrpcMessage(resp)
		if err != nil {
			return zeroOutput, fmt.Errorf("failed to store signed additional artifacts response: %w", err)
		}
		log.Get().Debugf("Signed additional artifacts response stored with path: %s", path)

		// We do not have prior knowledge of the expected instance key; for now, we just verify the signature's validity
		ok, err = crypto.VerifyDataSignature(resp.SerializedAdditionalArtifactsBundle, resp.Signature, resp.SigningKey)
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
		path, err = dot.StoreGrpcMessage(additionalArtifactsBundle)
		if err != nil {
			return zeroOutput, fmt.Errorf("failed to store additional artifacts bundle: %w", err)
		}
		log.Get().Debugf("Additional artifacts bundle stored with path: %s", path)
	}
	// This task needs {InstanceKey} from the AdditionalArtifactsBundle;
	instanceKey := additionalArtifactsBundle.InstanceKey
	if instanceKey == nil {
		return zeroOutput, fmt.Errorf("instance key is missing in the additional artifacts bundle")
	}
	output.InstanceKey = instanceKey

	nonce := generateRandomBytes()
	output.Nonce = nonce

	path, err = dot.Store(nonce[:])
	if err != nil {
		return zeroOutput, fmt.Errorf("failed to store nonce: %w", err)
	}
	log.Get().Debugf("Nonce stored with path: %s", path)

	req := &pb.GetEvidenceRequest{
		Nonce: nonce[:],
	}

	log.Get().Debugf("Requesting evidence")
	signedEvidenceBundle, err := client.GetEvidence(ctx, req)
	if err != nil {
		return zeroOutput, err
	}
	if signedEvidenceBundle == nil {
		return zeroOutput, fmt.Errorf("received nil response for evidence bundle")
	}

	ok, err := crypto.IsValidPublicKey(signedEvidenceBundle.SigningKey)
	if err != nil {
		return zeroOutput, fmt.Errorf("error while validating signing key in evidence bundle response: %w", err)
	}
	if !ok {
		return zeroOutput, fmt.Errorf("invalid signing key in evidence bundle response")
	}

	if !crypto.EqualPublicKeys(signedEvidenceBundle.SigningKey, instanceKey) {
		return zeroOutput, fmt.Errorf("signing key in evidence bundle response does not match instance key from additional artifacts bundle")
	}

	path, err = dot.Store(signedEvidenceBundle.SigningKey.Certificate.Data)
	if err != nil {
		return zeroOutput, fmt.Errorf("failed to store signing key certificate bytes: %w", err)
	}
	log.Get().Debugf("Signing key certificate bytes stored with path: %s", path)

	path, err = dot.StoreGrpcMessage(signedEvidenceBundle)
	if err != nil {
		return zeroOutput, fmt.Errorf("failed to store signed evidence bundle response: %w", err)
	}
	log.Get().Debugf("Signed evidence bundle response stored with path: %s", path)

	evidenceBundleBytes := signedEvidenceBundle.SerializedEvidenceBundle
	signature := signedEvidenceBundle.Signature
	signingKey := signedEvidenceBundle.SigningKey

	if signingKey == nil {
		return zeroOutput, fmt.Errorf("signing key is missing in the response")
	}

	if !crypto.EqualPublicKeys(signingKey, instanceKey) {
		return zeroOutput, fmt.Errorf("signing key in the response does not match the expected instance key")
	}

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

	path, err = dot.StoreGrpcMessage(&evidence)
	if err != nil {
		return zeroOutput, fmt.Errorf("failed to store evidence bundle: %w", err)
	}
	log.Get().Debugf("Evidence bundle stored with path: %s", path)

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

	path, err = dot.Store(snpEvidence.Raw().Bytes())
	if err != nil {
		return zeroOutput, fmt.Errorf("failed to store raw hardware evidence: %w", err)
	}
	log.Get().Debugf("Raw hardware evidence stored with path: %s", path)

	ok, err = crypto.IsValidPublicKey(snpEvidenceProto.SigningKey)
	if err != nil {
		return zeroOutput, fmt.Errorf("error while validating signing key in SNP evidence: %w", err)
	}
	if !ok {
		return zeroOutput, fmt.Errorf("invalid signing key in SNP evidence")
	}

	vcekCertProto := snpEvidenceProto.SigningKey.GetCertificate()
	if vcekCertProto == nil {
		return zeroOutput, fmt.Errorf("vcek certificate is missing")
	}

	vcekCertBytes := make([]byte, len(snpEvidenceProto.SigningKey.Certificate.Data))
	copy(vcekCertBytes, snpEvidenceProto.SigningKey.Certificate.Data)

	path, err = dot.Store(vcekCertBytes)
	if err != nil {
		return zeroOutput, fmt.Errorf("failed to store VCEK certificate bytes: %w", err)
	}
	log.Get().Debugf("VCEK certificate bytes stored with path: %s", path)

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

	path, err = dot.Store(tpmEvidence.Raw().Bytes())
	if err != nil {
		return zeroOutput, fmt.Errorf("failed to store raw TPM software evidence: %w", err)
	}
	log.Get().Debugf("Raw TPM software evidence stored with path: %s", path)

	ok, err = crypto.IsValidPublicKey(tpmEvidenceProto.SigningKey)
	if err != nil {
		return zeroOutput, fmt.Errorf("error while validating AK public key in TPM evidence: %w", err)
	}
	if !ok {
		return zeroOutput, fmt.Errorf("invalid AK public key in TPM evidence")
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
