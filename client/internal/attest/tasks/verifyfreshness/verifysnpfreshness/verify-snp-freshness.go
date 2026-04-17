package verifysnpfreshness

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
)

type Input struct {
	SnpEvidence  domain.HardwareEvidence[*domain.AmdSevSnpAttestationReport]
	Nonce        [64]byte
	InstanceCert *x509.Certificate
	AkCert       *x509.Certificate
	AkEc         *ecdsa.PublicKey
	AkRsa        *rsa.PublicKey
	Secret       []byte
}

type Output struct{}

func Task(ctx context.Context, input Input) (Output, error) {
	var err error

	report := input.SnpEvidence.Report()
	if report == nil {
		return Output{}, fmt.Errorf("SNP attestation report is nil")
	}

	log.Get().Debugln("Verifying freshness and artifact binding of the hardware evidence")
	log.Get().Debugf("Data: SHA512(nonce||rawInstanceKey||(akCert|rawAkKey)[||secret])")

	var instanceKeySPKIBytes []byte
	switch input.InstanceCert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		pubKey := input.InstanceCert.PublicKey.(*ecdsa.PublicKey)
		instanceKeySPKIBytes, err = x509.MarshalPKIXPublicKey(pubKey)
	case *rsa.PublicKey:
		pubKey := input.InstanceCert.PublicKey.(*rsa.PublicKey)
		instanceKeySPKIBytes, err = x509.MarshalPKIXPublicKey(pubKey)
	default:
		return Output{}, fmt.Errorf("unsupported instance key public key type: %T", input.InstanceCert.PublicKey)
	}
	if err != nil {
		return Output{}, fmt.Errorf("failed to marshal instance key public key: %w", err)
	}

	var akIdentifyingBytes []byte
	if input.AkCert != nil {
		akIdentifyingBytes = input.AkCert.Raw
	} else {
		switch {
		case input.AkEc != nil:
			akIdentifyingBytes, err = x509.MarshalPKIXPublicKey(input.AkEc)
		case input.AkRsa != nil:
			akIdentifyingBytes, err = x509.MarshalPKIXPublicKey(input.AkRsa)
		default:
			return Output{}, fmt.Errorf("no AK information provided: both AK certificate and public key are nil")
		}
		if err != nil {
			return Output{}, fmt.Errorf("failed to marshal AK public key: %w", err)
		}
	}

	buffer := bytes.Buffer{}
	buffer.Write(input.Nonce[:])
	buffer.Write(instanceKeySPKIBytes)
	buffer.Write(akIdentifyingBytes)
	if input.Secret != nil {
		buffer.Write(input.Secret)
	}
	digest := sha512.Sum512(buffer.Bytes())

	log.Get().Debugf("Computed digest: %s", hex.EncodeToString(digest[:]))
	log.Get().Debugf("Report data from the hardware evidence: %s", hex.EncodeToString(report.ReportData[:]))

	if digest != report.ReportData {
		return Output{}, fmt.Errorf("nonce mismatch, hardware evidence is not fresh")
	}
	log.Get().Debugln("Nonce matches the report data, hardware evidence is fresh")

	return Output{}, nil
}
