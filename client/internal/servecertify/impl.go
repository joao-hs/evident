package servecertify

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/crypto"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/packager"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/sanitize"
	pb "gitlab.com/dpss-inesc-id/achilles-cvm/client/pb/evident_protocol/v1"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/proto"
)

type certificateIssuerVerifierServiceImpl struct {
	pb.UnimplementedCertificateIssuerVerifierServiceServer

	caCerts []*x509.Certificate
	caKey   *ecdsa.PrivateKey

	gpgCmd string
}

func NewCertificateIssuerVerifierServiceImpl(caCerts []*x509.Certificate, caKey *ecdsa.PrivateKey) (pb.CertificateIssuerVerifierServiceServer, error) {
	c := &certificateIssuerVerifierServiceImpl{
		caCerts: caCerts,
		caKey:   caKey,
	}
	err := c.checkRequiredExternalCommands()
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (c *certificateIssuerVerifierServiceImpl) checkRequiredExternalCommands() error {
	var err error

	c.gpgCmd, err = exec.LookPath("gpg")
	if err != nil {
		return fmt.Errorf("`gpg` command is not present in PATH")
	}

	return nil
}

func (c *certificateIssuerVerifierServiceImpl) SubmitTrustedPackage(ctx context.Context, request *pb.MinimalPackage) (*pb.SignedPackageSubmissionResult, error) {
	var err error
	_ = ctx

	if len(request.SerializedManifest) == 0 {
		return nil, fmt.Errorf("missing serialized manifest")
	}
	if len(request.SerializedManifestSignature) == 0 {
		return nil, fmt.Errorf("missing manifest signatures")
	}
	if len(request.SerializedExpectedMeasurements) == 0 {
		return nil, fmt.Errorf("missing expected measurements")
	}

	// 1. Unmarshal expected measurements
	expectedPcrDigests := domain.ExpectedPcrDigests{}
	err = json.Unmarshal(request.SerializedExpectedMeasurements, &expectedPcrDigests)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal expected measurements: %w", err)
	}

	finalExpectedDigest, err := expectedPcrDigests.ComputeExpectedDigest(domain.ENUM_HASH_ALGORITHM_SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to compute expected digest from expected measurements: %w", err)
	}

	// 2. Create staging directory for the package

	if err := os.MkdirAll(trustedPackagesStagingDirPath, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create staging directory: %w", err)
	}

	stagingDirPath, err := os.MkdirTemp(
		trustedPackagesStagingDirPath,
		fmt.Sprintf("%s.package.", finalExpectedDigest),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create package staging directory: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(stagingDirPath)
	}()

	manifestPath := filepath.Join(stagingDirPath, packager.ManifestFileName)
	if err := os.WriteFile(manifestPath, request.SerializedManifest, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write manifest: %w", err)
	}

	expectedPcrsPath := filepath.Join(stagingDirPath, packager.ExpectedPcrsFileName)
	if err := os.WriteFile(expectedPcrsPath, request.SerializedExpectedMeasurements, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write expected measurements file: %w", err)
	}

	manifest, err := domain.ParseManifest(bytes.NewReader(request.SerializedManifest))
	if err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}

	// 3. Verify that the manifest's declared MOUT hash matches the expected measurements

	measuredSha512 := sha512.Sum512(request.SerializedExpectedMeasurements)
	measuredSha512Hex := hex.EncodeToString(measuredSha512[:])
	if !strings.EqualFold(manifest.ImageMeasurementsSha512, measuredSha512Hex) {
		return nil, fmt.Errorf("manifest MOUT hash does not match expected-pcrs.json")
	}

	// 4. Find valid signatures, check if any are trusted, and stage them with safe file names

	validSignatureFileNames := make([]string, 0, len(request.SerializedManifestSignature))
	hasTrustedSignature := false

	for i, sig := range request.SerializedManifestSignature {
		rawSigPath := filepath.Join(stagingDirPath, fmt.Sprintf("incoming-%d.sig.asc", i))
		if err := os.WriteFile(rawSigPath, sig, 0o644); err != nil {
			return nil, fmt.Errorf("failed to write signature %d: %w", i, err)
		}

		result, err := c.verifyManifestSignatureWithGPG(rawSigPath, manifestPath)
		if err != nil {
			return nil, fmt.Errorf("failed to verify signature %d: %w", i, err)
		}

		if !result.isValid {
			_ = os.Remove(rawSigPath)
			continue
		}

		if result.isTrusted {
			hasTrustedSignature = true
		}

		safeKeyID := result.signerKeyID
		if safeKeyID == "" {
			safeKeyID = fmt.Sprintf("UNKNOWN-%d", i)
		}

		destName := fmt.Sprintf("%s.sig.asc", safeKeyID)
		destPath := filepath.Join(stagingDirPath, destName)

		if err := os.Rename(rawSigPath, destPath); err != nil {
			return nil, fmt.Errorf("failed to rename signature file: %w", err)
		}

		validSignatureFileNames = append(validSignatureFileNames, destName)
	}

	if !hasTrustedSignature {
		return nil, fmt.Errorf("no signature is both valid and trusted")
	}

	// 5. Move staged package to final location

	finalPackageDirPath := filepath.Join(packager.TrustedPackagesDirPath, fmt.Sprintf("%s.package", finalExpectedDigest))

	if err := os.MkdirAll(packager.TrustedPackagesDirPath, 0o755); err != nil {
		return nil, fmt.Errorf("failed to ensure trusted-packages directory: %w", err)
	}

	// 6. If a package with the same expected digest already exists, check that its manifest and expected measurements match, and if so, overwrite signatures if they differ;
	// otherwise, move the staged package to the final location

	if info, statErr := os.Stat(finalPackageDirPath); statErr == nil {
		if !info.IsDir() {
			return nil, fmt.Errorf("destination path exists and is not a directory: %s", finalPackageDirPath)
		}

		existingManifest, err := os.ReadFile(filepath.Join(finalPackageDirPath, packager.ManifestFileName))
		if err != nil {
			return nil, fmt.Errorf("failed to read existing manifest: %w", err)
		}
		if !bytes.Equal(existingManifest, request.SerializedManifest) {
			return nil, fmt.Errorf("existing package manifest differs")
		}

		existingExpectedPcrs, err := os.ReadFile(filepath.Join(finalPackageDirPath, packager.ExpectedPcrsFileName))
		if err != nil {
			return nil, fmt.Errorf("failed to read existing expected-pcrs.json: %w", err)
		}
		if !bytes.Equal(existingExpectedPcrs, request.SerializedExpectedMeasurements) {
			return nil, fmt.Errorf("existing package expected-pcrs.json differs")
		}

		for _, sigName := range validSignatureFileNames {
			srcSigPath := filepath.Join(stagingDirPath, sigName)
			dstSigPath := filepath.Join(finalPackageDirPath, sigName)

			srcSigBytes, err := os.ReadFile(srcSigPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read staged signature %s: %w", sigName, err)
			}

			dstSigBytes, err := os.ReadFile(dstSigPath)
			if err == nil {
				if bytes.Equal(dstSigBytes, srcSigBytes) {
					continue
				}
				// overwrite existing signature if it differs
			}

			if err != nil && !os.IsNotExist(err) {
				return nil, fmt.Errorf("failed to check destination signature %s: %w", sigName, err)
			}

			if err := os.WriteFile(dstSigPath, srcSigBytes, 0o644); err != nil {
				return nil, fmt.Errorf("failed to write signature %s: %w", filepath.Base(dstSigPath), err)
			}
		}
	} else {
		if !os.IsNotExist(statErr) {
			return nil, fmt.Errorf("failed to check destination package directory: %w", statErr)
		}

		if err := os.Rename(stagingDirPath, finalPackageDirPath); err != nil {
			return nil, fmt.Errorf("failed to move trusted package to destination: %w", err)
		}
	}

	resultPayload, err := proto.Marshal(&pb.PackageSubmissionResult{Success: true})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal package submission result: %w", err)
	}

	return &pb.SignedPackageSubmissionResult{
		SerializedPackageSubmissionResult: resultPayload,
		Signature:                         nil, // TODO: sign response
		SigningKey:                        nil, // TODO: include signer key
	}, nil
}

const (
	trustedPackagesStagingDirPath = "/tmp/evident/trusted-packages"
)

type gpgSignatureVerificationResult struct {
	isValid     bool
	isTrusted   bool
	signerKeyID string
}

func (c *certificateIssuerVerifierServiceImpl) verifyManifestSignatureWithGPG(sigPath string, manifestPath string) (*gpgSignatureVerificationResult, error) {
	cmd := exec.Command(c.gpgCmd, "--batch", "--status-fd=1", "--verify", sigPath, manifestPath)

	statusOutput, err := cmd.CombinedOutput()
	statusLines := strings.Split(string(statusOutput), "\n")

	result := &gpgSignatureVerificationResult{}
	for _, line := range statusLines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "[GNUPG:] ") {
			continue
		}

		fields := strings.Fields(strings.TrimPrefix(line, "[GNUPG:] "))
		if len(fields) == 0 {
			continue
		}

		switch fields[0] {
		case "VALIDSIG":
			result.isValid = true
			if len(fields) > 1 {
				fingerprint := strings.ToUpper(fields[1])
				if len(fingerprint) >= 16 {
					candidate := fingerprint[len(fingerprint)-16:]
					if keyID, keyErr := sanitize.KeyId(candidate); keyErr == nil {
						result.signerKeyID = strings.ToUpper(keyID)
					}
				}
			}
		case "TRUST_ULTIMATE", "TRUST_FULLY", "TRUST_MARGINAL":
			result.isTrusted = true
		}
	}

	if !result.isValid {
		if err == nil {
			return result, nil
		}
		return result, nil
	}

	// If GPG declared a valid signature, ignore non-zero exit codes that may be
	// caused by trust warnings; trust is handled via status parsing above.
	return result, nil
}

func (c *certificateIssuerVerifierServiceImpl) RequestInstanceKeyAttestationCertificate(ctx context.Context, request *pb.SignedAdditionalArtifactsBundle) (*pb.SignedCertificateChain, error) {
	var (
		ok  bool
		err error
	)

	signingKeyEc, signingKeyRsa, err := crypto.ParsePublicKey(request.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signing key: %w", err)
	}
	if signingKeyEc == nil && signingKeyRsa == nil {
		return nil, fmt.Errorf("unsupported signing key type")
	}
	if signingKeyEc != nil && signingKeyRsa != nil {
		return nil, fmt.Errorf("multiple signing key types provided")
	}

	switch {
	case signingKeyEc != nil:
		ok, err = crypto.VerifyECDSASignature(request.SerializedAdditionalArtifactsBundle, request.Signature, signingKeyEc)
	case signingKeyRsa != nil:
		ok, err = crypto.VerifyRSASignature(request.SerializedAdditionalArtifactsBundle, request.Signature, signingKeyRsa)
	}
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("signature verification failed")
	}

	clientPeer, ok := peer.FromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("failed to get client from context")
	}

	clientAddrStr, _, err := net.SplitHostPort(clientPeer.Addr.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse client address: %w", err)
	}

	targetAddr, err := sanitize.TargetIP(clientAddrStr)
	if err != nil {
		return nil, fmt.Errorf("failed to sanitize client address: %w", err)
	}

	var additionalArtifactsBundle pb.AdditionalArtifactsBundle
	err = proto.Unmarshal(request.SerializedAdditionalArtifactsBundle, &additionalArtifactsBundle)
	if err != nil {
		return nil, err
	}

	target := additionalArtifactsBundle.TargetType
	var verifier attest.Verifier
	switch target {
	case pb.TargetType_TARGET_TYPE_SNP_EC2:
		verifier, err = attest.NewVerifierWithContext(
			ctx,
			domain.SecureHardwarePlatform(domain.ENUM_SECURE_HARDWARE_PLATFORM_AMD_SEV_SNP),
			domain.CloudServiceProvider(domain.ENUM_CLOUD_SERVICE_PROVIDER_AWS),
		)
	case pb.TargetType_TARGET_TYPE_SNP_GCE:
		verifier, err = attest.NewVerifierWithContext(
			ctx,
			domain.SecureHardwarePlatform(domain.ENUM_SECURE_HARDWARE_PLATFORM_AMD_SEV_SNP),
			domain.CloudServiceProvider(domain.ENUM_CLOUD_SERVICE_PROVIDER_GCP),
		)
	default:
		return nil, fmt.Errorf("unsupported target type: %s", target.String())
	}
	if err != nil {
		return nil, err
	}

	_, err = verifier.Attest(
		targetAddr,
		5000,
		nil, // Option: None -> Derive CPU count
		nil, // Option: None -> No EC2 endorsement of EK
		nil, // Option: None -> Use trusted packages
		&additionalArtifactsBundle,
	)
	if err != nil {
		return nil, err
	}

	csr := additionalArtifactsBundle.GetInstanceCsr()
	if csr == nil {
		return nil, fmt.Errorf("missing CSR in additional artifacts bundle")
	}

	if csr.Encoding != pb.CSREncoding_CSR_ENCODING_PEM {
		return nil, fmt.Errorf("unsupported CSR encoding: %s", csr.Encoding.String())
	}

	if csr.Format != pb.CSRFormat_CSR_FORMAT_PKCS10 {
		return nil, fmt.Errorf("unsupported CSR format: %s", csr.Format.String())
	}

	certChain, err := c.issueCertificate(csr.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to issue certificate: %w", err)
	}

	certChainBytes, err := proto.Marshal(certChain)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificate chain: %w", err)
	}

	return &pb.SignedCertificateChain{
		SerializedCertificateChain: certChainBytes,
		Signature:                  nil, // TODO: sign the certificate chain
		SigningKey:                 nil, // TODO: include the signing key or its identifier
	}, nil
}

func (c *certificateIssuerVerifierServiceImpl) attestSnpEc2(ctx context.Context, targetAddr netip.Addr, targetPort uint16, additionalArtifactsBundle *pb.AdditionalArtifactsBundle) error {
	verifier, err := attest.NewVerifierWithContext(
		ctx,
		domain.SecureHardwarePlatform(domain.ENUM_SECURE_HARDWARE_PLATFORM_AMD_SEV_SNP),
		domain.CloudServiceProvider(domain.ENUM_CLOUD_SERVICE_PROVIDER_AWS),
	)
	if err != nil {
		return err
	}

	_, err = verifier.Attest(targetAddr, targetPort, nil, nil, nil, additionalArtifactsBundle)
	return err
}

func (c *certificateIssuerVerifierServiceImpl) attestSnpGce(ctx context.Context, targetAddr netip.Addr, targetPort uint16, additionalArtifactsBundle *pb.AdditionalArtifactsBundle) error {
	verifier, err := attest.NewVerifierWithContext(
		ctx,
		domain.SecureHardwarePlatform(domain.ENUM_SECURE_HARDWARE_PLATFORM_AMD_SEV_SNP),
		domain.CloudServiceProvider(domain.ENUM_CLOUD_SERVICE_PROVIDER_AWS),
	)
	if err != nil {
		return err
	}

	_, err = verifier.Attest(targetAddr, targetPort, nil, nil, nil, additionalArtifactsBundle)
	return err
}

func (c *certificateIssuerVerifierServiceImpl) issueCertificate(csrPemBytes []byte) (*pb.CertificateChain, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	pemBlock, _ := pem.Decode(csrPemBytes)
	if pemBlock == nil || pemBlock.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("failed to decode PEM block containing CSR")
	}

	csr, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),

		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		EmailAddresses: csr.EmailAddresses,
		URIs:           csr.URIs,

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDer, err := x509.CreateCertificate(
		rand.Reader,
		template,
		c.caCerts[0],
		csr.PublicKey,
		c.caKey,
	)
	if err != nil {
		return nil, err
	}

	certs := make([]*pb.Certificate, 0, len(c.caCerts)+1)
	certs = append(certs, &pb.Certificate{
		Type:     pb.CertificateType_CERTIFICATE_TYPE_X509,
		Encoding: pb.CertificateEncoding_CERTIFICATE_ENCODING_DER,
		Data:     certDer,
	})
	for _, caCert := range c.caCerts {
		certs = append(certs, &pb.Certificate{
			Type:     pb.CertificateType_CERTIFICATE_TYPE_X509,
			Encoding: pb.CertificateEncoding_CERTIFICATE_ENCODING_DER,
			Data:     caCert.Raw,
		})
	}

	return &pb.CertificateChain{
		Certificates: certs,
	}, nil
}
