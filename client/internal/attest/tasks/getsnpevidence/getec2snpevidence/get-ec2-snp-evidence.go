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
	Client                       *grpc.AttesterServiceClient
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
	Vlek            *x509.Certificate
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

		switch {
		case ekEc != nil:
			output.EkEc = ekEc
			ekEcBytes, err := x509.MarshalPKIXPublicKey(ekEc)
			log.Get().Debugf("EC EK public key marshaled to bytes: %x", ekEcBytes)
			if err != nil {
				return zeroOutput, fmt.Errorf("error while converting EC EK public key to bytes: %w", err)
			}
			path, err = dot.Store(ekEcBytes)
			if err != nil {
				return zeroOutput, fmt.Errorf("error while storing EC EK public key bytes in dot: %w", err)
			}
		case ekRsa != nil:
			output.EkRsa = ekRsa
			ekRsaBytes, err := x509.MarshalPKIXPublicKey(ekRsa)
			log.Get().Debugf("RSA EK public key marshaled to bytes: %x", ekRsaBytes)
			if err != nil {
				return zeroOutput, fmt.Errorf("error while marshaling RSA EK public key: %w", err)
			}
			path, err = dot.Store(ekRsaBytes)
			if err != nil {
				return zeroOutput, fmt.Errorf("error while storing RSA EK public key bytes in dot: %w", err)
			}
		}

		var makeCredentialResult *makecred.Result
		switch {
		case ekEc != nil:
			makeCredentialResult, err = makecred.ECC(ekEc, secret[:], akName, makecred.Ec2EccEkParams())
		case ekRsa != nil:
			makeCredentialResult, err = makecred.RSA(ekRsa, secret[:], akName, makecred.Ec2RsaEkParams())
		}
		if err != nil {
			return zeroOutput, fmt.Errorf("error while making credential: %w", err)
		}
		activateCredentialBundle = &pb.ActivateCredentialBundle{
			CredentialBlob:  makeCredentialResult.CredentialBlob,
			EncryptedSecret: makeCredentialResult.EncryptedSecret,
		}
		path, err = dot.Store(activateCredentialBundle.CredentialBlob)
		if err != nil {
			return zeroOutput, fmt.Errorf("error while storing credential blob from make credential result in dot: %w", err)
		}
		log.Get().Debugf("Credential blob from make credential result stored in dot at path: %s", path)

		path, err = dot.Store(activateCredentialBundle.EncryptedSecret)
		if err != nil {
			return zeroOutput, fmt.Errorf("error while storing encrypted secret from make credential result in dot: %w", err)
		}
		log.Get().Debugf("Encrypted secret from make credential result stored in dot at path: %s", path)
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
			return zeroOutput, fmt.Errorf("error while parsing VLEK in SNP evidence: %w", err)
		}

		vlekCert, err := crypto.ParseCertificate(snpEvidenceProto.SigningKey.GetCertificate())
		if err != nil {
			return zeroOutput, fmt.Errorf("error while parsing VLEK certificate: %w", err)
		}

		path, err = dot.Store(vlekCert.Raw)
		if err != nil {
			return zeroOutput, fmt.Errorf("error while storing VLEK certificate bytes in dot: %w", err)
		}
		log.Get().Debugf("VLEK certificate bytes stored in dot at path: %s", path)
		output.Vlek = vlekCert
	}

	// infer model from VLEK certificate
	// TODO: ideally, we would infer the model from the SNP evidence itself
	{
		model, err := getsnpevidencesubtasks.ExtractModelFromCertIssuer(output.Vlek)
		if err != nil {
			return zeroOutput, fmt.Errorf("error while extracting model from VLEK certificate: %w", err)
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

		switch {
		case akEc != nil:
			akEcBytes, err := x509.MarshalPKIXPublicKey(akEc)
			log.Get().Debugf("AK EC public key marshaled to bytes: %x", akEcBytes)
			if err != nil {
				return zeroOutput, fmt.Errorf("error while converting AK EC public key to bytes: %w", err)
			}
			path, err = dot.Store(akEcBytes)
			if err != nil {
				return zeroOutput, fmt.Errorf("error while storing AK EC public key bytes in dot: %w", err)
			}
		case akRsa != nil:
			akRsaBytes, err := x509.MarshalPKIXPublicKey(akRsa)
			log.Get().Debugf("AK RSA public key marshaled to bytes: %x", akRsaBytes)
			if err != nil {
				return zeroOutput, fmt.Errorf("error while converting AK RSA public key to bytes: %w", err)
			}
			path, err = dot.Store(akRsaBytes)
			if err != nil {
				return zeroOutput, fmt.Errorf("error while storing AK RSA public key bytes in dot: %w", err)
			}
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
func fetchAdditionalArtifactsBundle(ctx context.Context, client *grpc.AttesterServiceClient) (*pb.AdditionalArtifactsBundle, error) {
	return getsnpevidencesubtasks.FetchAdditionalArtifactsBundle(ctx, client)
}
