package submitpackage

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/config"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/crypto"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/grpc"
	pb "gitlab.com/dpss-inesc-id/achilles-cvm/client/pb/evident_protocol/v1"
	"google.golang.org/protobuf/proto"
)

type PackageSubmitter interface {
	SubmitPackage(packageDirPath string) error
}

type packageSubmitter struct {
	ctx    context.Context
	client *grpc.CertificateIssuerVerifierServiceClient
}

func NewPackageSubmitter(targetAddrPort netip.AddrPort) (PackageSubmitter, error) {
	cfg := config.DefaultConfig()
	cfg.Addr = targetAddrPort.String()
	client, err := grpc.NewCertificateIssuerVerifierServiceClient(&cfg)
	if err != nil {
		return nil, err
	}

	return &packageSubmitter{
		ctx:    context.Background(),
		client: client,
	}, nil
}

const (
	expectedPcrsFileName = "expected-pcrs.json"
	manifestFileName     = "MANIFEST"
	signatureFileSuffix  = ".sig.asc"
)

func (p *packageSubmitter) SubmitPackage(packageDirPath string) error {
	// 1. Check if the necessary files are present in the package directory
	// Expected:
	/*
	 * <packageDirPath>/
	 * ├── expected-pcrs.json
	 * ├── MANIFEST
	 * ├── <KEY_ID>.sig.asc
	 * └── ...                // other .sig.asc files
	 */

	expectedPcrsFilePath := fmt.Sprintf("%s/%s", packageDirPath, expectedPcrsFileName)
	if !fileExists(expectedPcrsFilePath) {
		return fmt.Errorf("expected PCRs file is missing in package directory: %s", expectedPcrsFilePath)
	}
	serializedPcrsData, err := os.ReadFile(expectedPcrsFilePath)
	if err != nil {
		return fmt.Errorf("error while reading expected PCRs file in package directory: %w", err)
	}

	manifestFilePath := fmt.Sprintf("%s/%s", packageDirPath, manifestFileName)
	if !fileExists(manifestFilePath) {
		return fmt.Errorf("manifest file is missing in package directory: %s", manifestFilePath)
	}
	serializedManifestData, err := os.ReadFile(manifestFilePath)
	if err != nil {
		return fmt.Errorf("error while reading manifest file in package directory: %w", err)
	}

	signaturesFilePaths, err := findSignatureFiles(packageDirPath)
	if err != nil {
		return fmt.Errorf("error while finding signature files in package directory: %w", err)
	}
	if len(signaturesFilePaths) == 0 {
		return fmt.Errorf("no signature files found in package directory: %s", packageDirPath)
	}

	serializedSignaturesData := make([][]byte, 0, len(signaturesFilePaths))
	for _, sigFilePath := range signaturesFilePaths {
		if !fileExists(sigFilePath) {
			return fmt.Errorf("signature file is missing in package directory: %s", sigFilePath)
		}
		data, err := os.ReadFile(sigFilePath)
		if err != nil {
			return fmt.Errorf("error while reading signature file in package directory: %w", err)
		}
		serializedSignaturesData = append(serializedSignaturesData, data)
	}

	// 2. Create the message
	req := pb.MinimalPackage{
		SerializedExpectedMeasurements: serializedPcrsData,
		SerializedManifest:             serializedManifestData,
		SerializedManifestSignature:    serializedSignaturesData,
	}

	// 3. Send the message
	signedResp, err := p.client.SubmitPackage(p.ctx, &req)
	if err != nil {
		return fmt.Errorf("error while submitting package: %w", err)
	}

	// 4. Verify the response signature
	signedData := signedResp.GetSerializedPackageSubmissionResult()
	if signedData == nil {
		return fmt.Errorf("serialized package submission result is nil in response to package submission")
	}
	signature := signedResp.GetSignature()
	if signedData == nil {
		return fmt.Errorf("serialized package submission result is nil in response to package submission")
	}
	signingKey := signedResp.GetSigningKey()
	if signingKey == nil {
		return fmt.Errorf("signing key is nil in response to package submission")
	}
	signingKeyEc, signingKeyRsa, err := crypto.ParsePublicKey(signingKey)
	if err != nil {
		return fmt.Errorf("error while parsing signing key in response to package submission: %w", err)
	}
	if signingKeyEc == nil && signingKeyRsa == nil {
		return fmt.Errorf("signing key in response to package submission is not a valid EC or RSA public key")
	}
	if signingKeyEc != nil && signingKeyRsa != nil {
		return fmt.Errorf("signing key in response to package submission is both a valid EC and RSA public key, which should not be possible")
	}

	var ok bool
	switch {
	case signingKeyEc != nil:
		ok, err = crypto.VerifyECDSASignature(signedData, signature, signingKeyEc)
	case signingKeyRsa != nil:
		ok, err = crypto.VerifyRSASignature(signedData, signature, signingKeyRsa)
	}
	if err != nil {
		return fmt.Errorf("error while verifying signature in response to package submission: %w", err)
	}
	if !ok {
		return fmt.Errorf("invalid signature in response to package submission")
	}

	// 5. Unmarshal the package submission result and check the status
	submissionResult := &pb.PackageSubmissionResult{}
	err = proto.Unmarshal(signedData, submissionResult)
	if err != nil {
		return fmt.Errorf("error while unmarshaling package submission result in response to package submission: %w", err)
	}
	if !submissionResult.Success {
		return fmt.Errorf("package submission failed with message")
	}
	return nil
}

func fileExists(filePath string) bool {
	info, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func findSignatureFiles(dirPath string) ([]string, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("error while reading package directory: %w", err)
	}

	var sigFilePaths []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), signatureFileSuffix) {
			sigFilePaths = append(sigFilePaths, fmt.Sprintf("%s/%s", dirPath, entry.Name()))
		}
	}

	if len(sigFilePaths) == 0 {
		return nil, fmt.Errorf("no signature files found in package directory: %s", dirPath)
	}

	return sigFilePaths, nil
}
