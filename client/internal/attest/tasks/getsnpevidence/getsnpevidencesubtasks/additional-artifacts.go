package getsnpevidencesubtasks

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/crypto"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/dotevident"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/grpc"
	pb "gitlab.com/dpss-inesc-id/achilles-cvm/client/pb/evident_protocol/v1"
	"google.golang.org/protobuf/proto"
)

func FetchAdditionalArtifactsBundle(ctx context.Context, client *grpc.AttesterServiceClient) (*pb.AdditionalArtifactsBundle, error) {
	var (
		ok  bool
		err error
	)

	log.Get().Debugln("Requesting additional artifacts")
	resp, err := client.GetAdditionalArtifacts(ctx, &pb.GetAdditionalArtifactsRequest{})
	if err != nil {
		return nil, fmt.Errorf("error while requesting additional artifacts: %w", err)
	}
	if resp == nil {
		return nil, fmt.Errorf("additional artifacts bundle is nil in response")
	}
	signingKeyEc, signingKeyRsa, err := crypto.ParsePublicKey(resp.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("error while parsing signing key in additional artifacts bundle: %w", err)
	}
	if signingKeyEc == nil && signingKeyRsa == nil {
		return nil, fmt.Errorf("signing key in additional artifacts bundle is not a valid EC or RSA public key")
	}
	if signingKeyEc != nil && signingKeyRsa != nil {
		return nil, fmt.Errorf("signing key in additional artifacts bundle is both a valid EC and RSA public key, which should not be possible")
	}

	switch {
	case signingKeyEc != nil:
		ok, err = crypto.VerifyECDSASignature(resp.SerializedAdditionalArtifactsBundle, resp.Signature, signingKeyEc)
	case signingKeyRsa != nil:
		ok, err = crypto.VerifyRSASignature(resp.SerializedAdditionalArtifactsBundle, resp.Signature, signingKeyRsa)
	}
	if err != nil {
		return nil, fmt.Errorf("error while verifying signature of additional artifacts bundle: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("invalid signature of additional artifacts bundle")
	}

	path, err := dotevident.Get().StoreGrpcMessage(resp)
	if err != nil {
		return nil, fmt.Errorf("error while storing additional artifacts bundle in dot: %w", err)
	}
	log.Get().Debugf("Additional artifacts bundle stored in dot with path: %s", path)

	var additionalArtifactsBundle = &pb.AdditionalArtifactsBundle{}
	err = proto.Unmarshal(resp.SerializedAdditionalArtifactsBundle, additionalArtifactsBundle)
	if err != nil {
		return nil, fmt.Errorf("error while unmarshaling additional artifacts bundle: %w", err)
	}

	path, err = dotevident.Get().StoreGrpcMessage(additionalArtifactsBundle)
	if err != nil {
		return nil, fmt.Errorf("error while storing unmarshaled additional artifacts bundle in dot: %w", err)
	}
	log.Get().Debugf("Unmarshaled additional artifacts bundle stored in dot with path: %s", path)

	// instanceKey := additionalArtifactsBundle.GetInstanceKey()
	// if instanceKey != nil {
	// 	instanceKeyEc, instanceKeyRsa, err := crypto.ParsePublicKey(instanceKey)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("error while parsing instance key from additional artifacts bundle: %w", err)
	// 	}
	// 	if instanceKeyEc == nil && instanceKeyRsa == nil {
	// 		return nil, fmt.Errorf("instance key in additional artifacts bundle is not a valid EC or RSA public key")
	// 	}
	// 	if instanceKeyEc != nil && instanceKeyRsa != nil {
	// 		return nil, fmt.Errorf("instance key in additional artifacts bundle is both a valid EC and RSA public key, which should not be possible")
	// 	}

	// 	switch {
	// 	case instanceKeyEc != nil:
	// 		ok = crypto.EqualECDSAPublicKeys(signingKeyEc, instanceKeyEc)
	// 	case instanceKeyRsa != nil:
	// 		ok = crypto.EqualRSAPublicKeys(signingKeyRsa, instanceKeyRsa)
	// 	}
	// 	if !ok {
	// 		return nil, fmt.Errorf("signing key in additional artifacts bundle does not match signing key of additional artifacts bundle")
	// 	}

	// 	instanceKeyCertProto := instanceKey.GetCertificate()
	// 	if instanceKeyCertProto == nil {
	// 		log.Get().Warnln("Instance key certificate is missing in additional artifacts bundle, skipping storing it in dot")
	// 		return additionalArtifactsBundle, nil
	// 	}

	// 	instanceKeyCert, err := crypto.ParseCertificate(instanceKeyCertProto)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("error while parsing instance key certificate from additional artifacts bundle: %w", err)
	// 	}

	// 	path, err = dotevident.Get().Store(instanceKeyCert.Raw)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("error while storing instance key certificate in dot: %w", err)
	// 	}
	// 	log.Get().Debugf("Instance key certificate of stored in dot at path: %s", path)
	// }

	return additionalArtifactsBundle, nil
}

func ValidateAdditionalArtifactsBundle(
	additionalArtifactsBundle *pb.AdditionalArtifactsBundle,
	expectedTargetType pb.TargetType,
) (
	outputInstanceKeyCertificate *x509.Certificate,
	outputMakeCredentialInputBundle *pb.MakeCredentialInputBundle,
	outputInstanceCsr *x509.CertificateRequest,
	outputGrpcServerCertificate *x509.Certificate,
	err error,
) {
	if additionalArtifactsBundle == nil {
		err = fmt.Errorf("additional artifacts bundle is nil")
		return
	}

	if additionalArtifactsBundle.GetTargetType() != expectedTargetType {
		err = fmt.Errorf("additional artifacts bundle target type does not match expected output target type")
		return
	}

	// InstanceKey: required with certificate
	outputInstanceKey := additionalArtifactsBundle.GetInstanceKey()
	if outputInstanceKey == nil {
		err = fmt.Errorf("instance key is missing in the additional artifacts bundle")
		return
	}
	var (
		outputInstanceKeyEc  *ecdsa.PublicKey
		outputInstanceKeyRsa *rsa.PublicKey
	)
	outputInstanceKeyEc, outputInstanceKeyRsa, err = crypto.ParsePublicKey(outputInstanceKey)
	if err != nil {
		err = fmt.Errorf("error while parsing instance key from additional artifacts bundle: %w", err)
		return
	}
	if outputInstanceKeyEc == nil && outputInstanceKeyRsa == nil {
		err = fmt.Errorf("instance key in additional artifacts bundle is not a valid EC or RSA public key")
		return
	}
	if outputInstanceKeyEc != nil && outputInstanceKeyRsa != nil {
		err = fmt.Errorf("instance key in additional artifacts bundle is both a valid EC and RSA public key, which should not be possible")
		return
	}

	outputInstanceKeyCertProto := outputInstanceKey.GetCertificate()
	if outputInstanceKeyCertProto == nil {
		err = fmt.Errorf("instance key certificate is missing in additional artifacts bundle")
		return
	}

	outputInstanceKeyCertificate, err = crypto.ParseCertificate(outputInstanceKeyCertProto)
	if err != nil {
		err = fmt.Errorf("error while parsing instance key certificate from additional artifacts bundle: %w", err)
		return
	}

	var path string
	path, err = dotevident.Get().Store(outputInstanceKeyCertificate.Raw)
	if err != nil {
		err = fmt.Errorf("error while storing instance key certificate in dot: %w", err)
		return
	}
	log.Get().Debugf("Instance key certificate of stored in dot at path: %s", path)

	// MakeCredentialInputBundle: optional
	outputMakeCredentialInputBundle = additionalArtifactsBundle.GetMakeCredentialInput()
	if outputMakeCredentialInputBundle != nil {
		var path string
		path, err = dotevident.Get().StoreGrpcMessage(outputMakeCredentialInputBundle)
		if err != nil {
			err = fmt.Errorf("error while storing make credential input bundle from additional artifacts bundle in dotevident: %w", err)
			return
		}
		log.Get().Debugf("Stored make credential input bundle from additional artifacts bundle in dotevident with path: %s\n", path)
	}

	// Instance CSR: optional, but if present, must match instance key certificate
	outputInstanceCsrProto := additionalArtifactsBundle.GetInstanceCsr()
	if outputInstanceCsrProto != nil {
		var csr *x509.CertificateRequest
		csr, err = crypto.ParseCSR(outputInstanceCsrProto)
		if err != nil {
			err = fmt.Errorf("error while parsing instance CSR in additional artifacts bundle: %w", err)
			return
		}

		if !crypto.CSRMatchesCertificate(csr, outputInstanceKeyCertificate) {
			err = fmt.Errorf("instance CSR in additional artifacts bundle does not match instance key certificate in additional artifacts bundle")
			return
		}
	}

	// gRPC server certificate: optional
	grpcServerCertificateProto := additionalArtifactsBundle.GetGrpcServerCertificate()
	if grpcServerCertificateProto != nil {
		outputGrpcServerCertificate, err = crypto.ParseCertificate(grpcServerCertificateProto)
		if err != nil {
			err = fmt.Errorf("error while parsing gRPC server certificate from additional artifacts bundle: %w", err)
			return
		}
	}

	err = nil
	return
}
