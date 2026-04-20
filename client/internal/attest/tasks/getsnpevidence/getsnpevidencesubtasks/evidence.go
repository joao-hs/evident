package getsnpevidencesubtasks

import (
	"context"
	"crypto/x509"
	"fmt"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/crypto"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/dotevident"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/grpc"
	pb "gitlab.com/dpss-inesc-id/achilles-cvm/client/pb/evident_protocol/v1"
	"google.golang.org/protobuf/proto"
)

func FetchEvidenceBundle(
	ctx context.Context,
	client *grpc.AttesterServiceClient,
	request *pb.GetEvidenceRequest,
	expectedSigningKeyCertificate *x509.Certificate,
) (*pb.EvidenceBundle, error) {
	var (
		ok  bool
		err error
	)

	log.Get().Debugln("Requesting evidence")
	signedEvidenceBundle, err := client.GetEvidence(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("error while requesting evidence bundle: %w", err)
	}
	if signedEvidenceBundle == nil {
		return nil, fmt.Errorf("evidence bundle is nil in response")
	}

	signingKeyEc, signingKeyRsa, err := crypto.ParsePublicKey(signedEvidenceBundle.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("error while parsing signing key in evidence bundle: %w", err)
	}
	if signingKeyEc == nil && signingKeyRsa == nil {
		return nil, fmt.Errorf("signing key in evidence bundle is not a valid EC or RSA public key")
	}
	if signingKeyEc != nil && signingKeyRsa != nil {
		return nil, fmt.Errorf("signing key in evidence bundle is both a valid EC and RSA public key, which should not be possible")
	}

	switch {
	case signingKeyEc != nil:
		if !crypto.CertificateMatchesECDSAPublicKey(expectedSigningKeyCertificate, signingKeyEc) {
			return nil, fmt.Errorf("signing key in evidence bundle does not match expected signing key certificate")
		}
		ok, err = crypto.VerifyECDSASignature(signedEvidenceBundle.SerializedEvidenceBundle, signedEvidenceBundle.Signature, signingKeyEc)
	case signingKeyRsa != nil:
		if !crypto.CertificateMatchesRSAPublicKey(expectedSigningKeyCertificate, signingKeyRsa) {
			return nil, fmt.Errorf("signing key in evidence bundle does not match expected signing key certificate")
		}
		ok, err = crypto.VerifyRSASignature(signedEvidenceBundle.SerializedEvidenceBundle, signedEvidenceBundle.Signature, signingKeyRsa)
	}
	if err != nil {
		return nil, fmt.Errorf("error while verifying signature of evidence bundle: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("invalid signature of evidence bundle")
	}

	path, err := dotevident.Get().Store(signedEvidenceBundle.SigningKey.Certificate.Data)
	if err != nil {
		return nil, fmt.Errorf("error while storing signing key certificate of evidence bundle in dot: %w", err)
	}
	log.Get().Debugf("Signing key certificate of evidence bundle stored in dot at path: %s", path)

	var evidenceBundle = &pb.EvidenceBundle{}
	err = proto.Unmarshal(signedEvidenceBundle.SerializedEvidenceBundle, evidenceBundle)
	if err != nil {
		return nil, fmt.Errorf("error while unmarshaling evidence bundle: %w", err)
	}

	return evidenceBundle, nil
}
