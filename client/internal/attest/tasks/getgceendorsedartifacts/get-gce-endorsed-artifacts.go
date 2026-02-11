package getgceendorsedartifacts

import (
	"bytes"
	"context"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"

	"cloud.google.com/go/storage"
	"github.com/google/gce-tcb-verifier/proto/endorsement"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/proto"
)

const (
	googleLaunchEndorsementBucket      = "gce_tcb_integrity"
	googleProvidedOvmfBinaryBucket     = "gce_tcb_integrity"
	googleLaunchEndorsementObjectTmpl  = "ovmf_x64_csm/sevsnp/%s.binarypb" // measurement in hex
	googleProvidedOvmfBinaryObjectTmpl = "ovmf_x64_csm/%s.fd"              // uefi true digest in hex
	googleRootKeyCertUrl               = "https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt"
)

type Input struct {
	CPUCount   uint32
	HwEvidence domain.HardwareEvidence[*domain.AmdSevSnpAttestationReport]
}

type Output struct {
	OvmfBinaryBytes []byte
}

func Task(ctx context.Context, input Input) (Output, error) {
	var zeroOutput Output

	report := input.HwEvidence.Report()
	var measurementBytes [48]byte
	copy(measurementBytes[:], report.Measurement[:])

	measurementHex := hex.EncodeToString(measurementBytes[:])

	client, err := storage.NewClient(ctx, option.WithoutAuthentication())
	if err != nil {
		return zeroOutput, err
	}
	defer client.Close()

	log.Get().Debugf("Fetching launch endorsement from Google Cloud Storage for measurement %s\n", measurementHex)
	endorsementStorageReader, err := client.
		Bucket(googleLaunchEndorsementBucket).
		Object(fmt.Sprintf(googleLaunchEndorsementObjectTmpl, measurementHex)).
		NewReader(ctx)
	if err != nil {
		return zeroOutput, err
	}
	defer endorsementStorageReader.Close()

	launchEndorsementBytes := bytes.NewBuffer(nil)
	if _, err := io.Copy(launchEndorsementBytes, endorsementStorageReader); err != nil {
		return zeroOutput, err
	}
	log.Get().Debugln("Launch endorsement received")

	launchEndorsement := &endorsement.VMLaunchEndorsement{}
	if err := proto.Unmarshal(launchEndorsementBytes.Bytes(), launchEndorsement); err != nil {
		return zeroOutput, err
	}

	launchEndorsementSignedData := launchEndorsement.GetSerializedUefiGolden()
	if launchEndorsementSignedData == nil {
		return zeroOutput, fmt.Errorf("launch endorsement signed data is nil")
	}
	log.Get().Debugf("Launch endorsement signed data: %s\n", hex.EncodeToString(launchEndorsementSignedData))

	launchEndorsementSignature := launchEndorsement.GetSignature()
	if launchEndorsementSignature == nil {
		return zeroOutput, fmt.Errorf("launch endorsement signature is nil")
	}
	log.Get().Debugf("Launch endorsement signature: %s\n", hex.EncodeToString(launchEndorsementSignature))

	googleGoldenMeasurement := &endorsement.VMGoldenMeasurement{}
	if err := proto.Unmarshal(launchEndorsement.GetSerializedUefiGolden(), googleGoldenMeasurement); err != nil {
		return zeroOutput, err
	}

	launchEndorsementCertificateBytes := googleGoldenMeasurement.GetCert()
	if launchEndorsementCertificateBytes == nil {
		return zeroOutput, fmt.Errorf("launch endorsement certificate is nil")
	}
	log.Get().Debugf("Launch endorsement certificate: %s\n", hex.EncodeToString(launchEndorsementCertificateBytes))

	launchEndorsementCertificate, err := x509.ParseCertificate(launchEndorsementCertificateBytes)
	if err != nil {
		return zeroOutput, err
	}

	log.Get().Debugln("Verifying launch endorsement signature")
	err = launchEndorsementCertificate.CheckSignature(launchEndorsementCertificate.SignatureAlgorithm, launchEndorsementSignedData, launchEndorsementSignature)
	if err != nil {
		return zeroOutput, fmt.Errorf("failed to verify launch endorsement signature: %w", err)
	}
	log.Get().Debugln("Launch endorsement signature verified successfully")

	uefiTrueDigest := googleGoldenMeasurement.GetDigest()
	if uefiTrueDigest == nil {
		return zeroOutput, fmt.Errorf("uefi digest is nil")
	}
	log.Get().Debugf("Advertised UEFI sha256sum in launch endorsement: %s\n", hex.EncodeToString(uefiTrueDigest))

	googleSevSnp := googleGoldenMeasurement.GetSevSnp()
	if googleSevSnp == nil {
		return zeroOutput, fmt.Errorf("google sev-snp info is nil")
	}

	googleUefiLaunchDigestMeasurements := googleSevSnp.GetMeasurements()
	if googleUefiLaunchDigestMeasurements == nil {
		return zeroOutput, fmt.Errorf("google uefi launch digest measurements is nil")
	}

	googleUefiLaunchDigest := googleUefiLaunchDigestMeasurements[input.CPUCount]
	if googleUefiLaunchDigest == nil {
		return zeroOutput, fmt.Errorf("google uefi launch digest for cpu count %d is nil", input.CPUCount)
	}

	if len(googleUefiLaunchDigest) != 48 {
		return zeroOutput, fmt.Errorf("google uefi launch digest for cpu count %d has invalid length: %d", input.CPUCount, len(googleUefiLaunchDigest))
	}
	log.Get().Debugf("Advertised UEFI launch digest for CPU count %d in launch endorsement: %s\n", input.CPUCount, hex.EncodeToString(googleUefiLaunchDigest))

	log.Get().Debugln("Comparing advertised UEFI launch digest with actual report measurement")
	reportUefiLaunchDigest := report.Measurement[:]
	if !bytes.Equal(googleUefiLaunchDigest, reportUefiLaunchDigest) {
		return zeroOutput, fmt.Errorf("uefi launch digest does not match report measurement")
	}
	log.Get().Debugln("Advertised UEFI launch digest matches report measurement")

	log.Get().Debugln("Getting Google's Root CA certificate for launch endorsement verification")
	resp, err := http.Get(googleRootKeyCertUrl)
	if err != nil {
		return zeroOutput, fmt.Errorf("failed to fetch root key certificate: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return zeroOutput, fmt.Errorf("unexpected status code when fetching root key certificate: %d", resp.StatusCode)
	}

	rootKeyCertBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return zeroOutput, fmt.Errorf("failed to read root key certificate: %w", err)
	}
	log.Get().Debugf("Received Google's Root CA certificate: %s\n", hex.EncodeToString(rootKeyCertBytes))

	rootKeyCert, err := x509.ParseCertificate(rootKeyCertBytes)
	if err != nil {
		return zeroOutput, fmt.Errorf("failed to parse root key certificate: %w", err)
	}

	log.Get().Debugln("Verifying launch endorsement certificate signature with Google's Root CA certificate")
	err = launchEndorsementCertificate.CheckSignatureFrom(rootKeyCert)
	if err != nil {
		return zeroOutput, fmt.Errorf("failed to verify launch endorsement certificate signature: %w", err)
	}
	log.Get().Debugln("Launch endorsement certificate signature verified successfully with Google's Root CA certificate")

	uefiTrueDigestHex := hex.EncodeToString(uefiTrueDigest)

	log.Get().Debugln("Fetching the UEFI binary from Google Cloud Storage")
	ovmfStorageReader, err := client.
		Bucket(googleProvidedOvmfBinaryBucket).
		Object(fmt.Sprintf(googleProvidedOvmfBinaryObjectTmpl, uefiTrueDigestHex)).
		NewReader(ctx)
	if err != nil {
		return zeroOutput, err
	}
	defer ovmfStorageReader.Close()

	ovmfBinary := bytes.NewBuffer(nil)
	if _, err := io.Copy(ovmfBinary, ovmfStorageReader); err != nil {
		return zeroOutput, err
	}

	ovmfBinaryBytes := ovmfBinary.Bytes()
	if len(ovmfBinaryBytes) == 0 {
		return zeroOutput, fmt.Errorf("downloaded OVMF binary is empty")
	}
	log.Get().Debugf("UEFI binary fetched successfully: %s\n", hex.EncodeToString(ovmfBinaryBytes))

	log.Get().Debugln("Verifying the integrity of the fetched UEFI binary")
	hasher := sha512.New384()
	if _, err := hasher.Write(ovmfBinaryBytes); err != nil {
		return zeroOutput, err
	}
	calculatedDigest := hasher.Sum(nil)

	if !bytes.Equal(calculatedDigest, uefiTrueDigest) {
		return zeroOutput, fmt.Errorf("calculated OVMF binary digest does not match UEFI endorsed digest")
	}
	log.Get().Debugln("UEFI binary integrity verified successfully")

	return Output{
		OvmfBinaryBytes: ovmfBinaryBytes,
	}, nil
}
