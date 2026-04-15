package getec2snpevidence

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/getsnpevidence/getsnpevidencesubtasks"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest/tasks/getsnpevidence/makecred"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/crypto"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/dotevident"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/grpc"
	pb "gitlab.com/dpss-inesc-id/achilles-cvm/client/pb/evident_protocol/v1"
)

type Input struct {
	Client                       *grpc.Client
	OptAdditionalArtifactsBundle *pb.AdditionalArtifactsBundle
}

type Output struct {
	InstanceKeyCert *x509.Certificate
	EkEc            *ecdsa.PublicKey
	EkRsa           *rsa.PublicKey
	Secret          [64]byte
	Nonce           [64]byte
	Model           domain.AMDSEVSNPModel
	HwEvidence      domain.HardwareEvidence[*domain.AmdSevSnpAttestationReport]
	Vcek            *x509.Certificate
	SwEvidence      domain.SoftwareEvidence
	AkEc            *ecdsa.PublicKey
	AkRsa           *rsa.PublicKey
}

func Task(ctx context.Context, input Input) (Output, error) {
	var (
		dot        = dotevident.Get()
		path       string
		zeroOutput Output
		output     Output
		err        error
	)

	var (
		client                    = input.Client
		additionalArtifactsBundle = input.OptAdditionalArtifactsBundle
	)

	if additionalArtifactsBundle == nil {
		additionalArtifactsBundle, err = fetchAdditionalArtifactsBundle(ctx, client)
		if err != nil {
			return zeroOutput, fmt.Errorf("error while getting additional artifacts: %w", err)
		}
	}

	instanceKeyCert, makeCredentialInput, _, _, err := getsnpevidencesubtasks.ValidateAdditionalArtifactsBundle(additionalArtifactsBundle, pb.TargetType_TARGET_TYPE_SNP_EC2)
	if err != nil {
		return zeroOutput, fmt.Errorf("error while validating additional artifacts bundle: %w", err)
	}
	output.InstanceKeyCert = instanceKeyCert

	var activateCredentialBundle *pb.ActivateCredentialBundle
	{
		if makeCredentialInput == nil {
			return zeroOutput, fmt.Errorf("make credential input is nil in additional artifacts bundle")
		}
		ekProto := makeCredentialInput.GetTpmEndorsementKey()
		if ekProto == nil {
			return zeroOutput, fmt.Errorf("TPM endorsement key is nil in make credential input bundle")
		}
		akName := makeCredentialInput.GetTpmAttestationKeyName()
		if akName == nil {
			return zeroOutput, fmt.Errorf("TPM platform attestation key is nil in make credential input bundle")
		}

		secret := getsnpevidencesubtasks.GenerateRandomBytes()
		output.Secret = secret

		ekEc, ekRsa, err := crypto.ParsePublicKey(ekProto)
		if err != nil {
			return zeroOutput, fmt.Errorf("error while parsing TPM endorsement key from make credential input bundle: %w", err)
		}
		if ekEc == nil && ekRsa == nil {
			return zeroOutput, fmt.Errorf("TPM endorsement key in make credential input bundle is not a valid EC or RSA public key")
		}
		if ekEc != nil && ekRsa != nil {
			return zeroOutput, fmt.Errorf("TPM endorsement key in make credential input bundle is both a valid EC and RSA public key, which should not be possible")
		}

		var makeCredentialResult *makecred.Result
		switch {
		case ekEc != nil:
			makeCredentialResult, err = makecred.ECC(ekEc, secret[:], akName, makecred.DefaultParams())
		case ekRsa != nil:
			makeCredentialResult, err = makecred.RSA(ekRsa, secret[:], akName, makecred.DefaultParams())
		}
		if err != nil {
			return zeroOutput, fmt.Errorf("error while making credential: %w", err)
		}
		activateCredentialBundle = &pb.ActivateCredentialBundle{
			CredentialBlob:  makeCredentialResult.CredentialBlob,
			EncryptedSecret: makeCredentialResult.EncryptedSecret,
		}
	}

	var getEvidenceRequest = &pb.GetEvidenceRequest{}
	{
		nonce := getsnpevidencesubtasks.GenerateRandomBytes()
		path, err = dot.Store(nonce[:])
		if err != nil {
			return zeroOutput, fmt.Errorf("error while storing nonce in dot: %w", err)
		}
		log.Get().Debugf("Nonce stored in dot at path: %s", path)
		getEvidenceRequest.Nonce = nonce[:]
		getEvidenceRequest.ActivateCredentialBundle = activateCredentialBundle
		output.Nonce = nonce
	}

	var evidenceBundle *pb.EvidenceBundle
	{
		evidenceBundle, err = getsnpevidencesubtasks.FetchEvidenceBundle(ctx, client, getEvidenceRequest, instanceKeyCert)
		if err != nil {
			return zeroOutput, fmt.Errorf("error while getting evidence bundle: %w", err)
		}
		path, err = dot.StoreGrpcMessage(evidenceBundle)
		if err != nil {
			return zeroOutput, fmt.Errorf("error while storing evidence bundle in dot: %w", err)
		}
		log.Get().Debugf("Evidence bundle stored in dot with path: %s", path)
	}

	var snpEvidenceProto *pb.Evidence
	{
		hardwareEvidenceWrapper, ok := evidenceBundle.HardwareEvidence.(*pb.EvidenceBundle_SnpEvidence)
		if !ok || hardwareEvidenceWrapper == nil || hardwareEvidenceWrapper.SnpEvidence == nil {
			return zeroOutput, fmt.Errorf("hardware evidence in evidence bundle is not of type SNP evidence")
		}
		snpEvidenceProto = hardwareEvidenceWrapper.SnpEvidence
	}

	var tpmEvidenceProto *pb.Evidence
	{
		softwareEvidenceWrapper, ok := evidenceBundle.SoftwareEvidence.(*pb.EvidenceBundle_TpmEvidence)
		if !ok || softwareEvidenceWrapper == nil || softwareEvidenceWrapper.TpmEvidence == nil {
			return zeroOutput, fmt.Errorf("software evidence in evidence bundle is not of type TPM evidence")
		}
		tpmEvidenceProto = softwareEvidenceWrapper.TpmEvidence
	}

	// validate SNP Evidence signing key and signing key certificate
	{
		_, err := crypto.ParseECDSAPublicKey(snpEvidenceProto.SigningKey)
		if err != nil {
			return zeroOutput, fmt.Errorf("error while parsing VCEK in SNP evidence: %w", err)
		}

		vcekCert, err := crypto.ParseCertificate(snpEvidenceProto.SigningKey.GetCertificate())
		if err != nil {
			return zeroOutput, fmt.Errorf("error while parsing VCEK certificate: %w", err)
		}

		path, err = dot.Store(vcekCert.Raw)
		if err != nil {
			return zeroOutput, fmt.Errorf("error while storing VCEK certificate bytes in dot: %w", err)
		}
		log.Get().Debugf("VCEK certificate bytes stored in dot at path: %s", path)
		output.Vcek = vcekCert
	}

	// infer model from VCEK certificate
	// TODO: ideally, we would infer the model from the SNP evidence itself
	{
		model, err := getsnpevidencesubtasks.ExtractModelFromVcekCertIssuer(output.Vcek)
		if err != nil {
			return zeroOutput, fmt.Errorf("error while extracting model from VCEK certificate: %w", err)
		}
		output.Model = model
	}

	var snpEvidence domain.HardwareEvidence[*domain.AmdSevSnpAttestationReport]
	{
		snpEvidence, err = domain.NewAMDSEVSNPHardwareEvidence(output.Model, snpEvidenceProto)
		if err != nil {
			return zeroOutput, fmt.Errorf("error while creating SNP hardware evidence from proto: %w", err)
		}
		output.HwEvidence = snpEvidence
		path, err = dot.Store(snpEvidence.Raw().Bytes())
		if err != nil {
			return zeroOutput, fmt.Errorf("error while storing raw SNP hardware evidence in dot: %w", err)
		}
		log.Get().Debugf("Raw SNP hardware evidence stored in dot at path: %s", path)
	}

	// validate TPM Evidence signing key
	// there is no signing key (AK) certificate
	{
		akEc, akRsa, err := crypto.ParsePublicKey(tpmEvidenceProto.SigningKey)
		if err != nil {
			return zeroOutput, fmt.Errorf("error while parsing signing key in TPM evidence: %w", err)
		}
		if akEc == nil && akRsa == nil {
			return zeroOutput, fmt.Errorf("signing key in TPM evidence is not a valid EC or RSA public key")
		}
		if akEc != nil && akRsa != nil {
			return zeroOutput, fmt.Errorf("signing key in TPM evidence is both a valid EC and RSA public key, which should not be possible")
		}

		output.AkEc = akEc
		output.AkRsa = akRsa
	}

	var tpmEvidence domain.SoftwareEvidence
	{
		tpmEvidence, err = domain.NewTPMSoftwareEvidence(domain.CloudServiceProvider(domain.ENUM_CLOUD_SERVICE_PROVIDER_GCP), tpmEvidenceProto.SignedRaw, tpmEvidenceProto.Signature)
		if err != nil {
			return zeroOutput, fmt.Errorf("error while creating TPM software evidence from proto: %w", err)
		}
		path, err = dot.Store(tpmEvidence.Raw().Bytes())
		if err != nil {
			return zeroOutput, fmt.Errorf("error while storing raw TPM software evidence in dot: %w", err)
		}
		log.Get().Debugf("Raw TPM software evidence stored in dot at path: %s", path)
		output.SwEvidence = tpmEvidence
	}

	return output, nil
}

// fetchAdditionalArtifactsBundle requests the additional artifacts bundle from the server, verifies its signature, and returns the unmarshaled additional artifacts bundle.
func fetchAdditionalArtifactsBundle(ctx context.Context, client *grpc.Client) (*pb.AdditionalArtifactsBundle, error) {
	return getsnpevidencesubtasks.FetchAdditionalArtifactsBundle(ctx, client)
}
