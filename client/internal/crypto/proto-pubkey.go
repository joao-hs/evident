package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	pb "gitlab.com/dpss-inesc-id/achilles-cvm/client/pb/evident_protocol/v1"
)

func EqualPublicKeys(key1, key2 *pb.PublicKey) bool {
	if key1 == nil || key2 == nil {
		return false
	}

	if key1.Algorithm != key2.Algorithm {
		return false
	}

	switch key1.Algorithm {
	case pb.KeyAlgorithm_KEY_ALGORITHM_EC:
		if key1.GetEllipticCurve() != key2.GetEllipticCurve() {
			return false
		}
		if key1.GetEllipticCurve() == pb.EllipticCurve_ELLIPTIC_CURVE_UNSPECIFIED {
			return false
		}
	case pb.KeyAlgorithm_KEY_ALGORITHM_RSA:
		if key1.GetRsaKeySize() != key2.GetRsaKeySize() {
			return false
		}
		if key1.GetRsaKeySize() == pb.RsaKeySize_RSA_KEY_SIZE_UNSPECIFIED {
			return false
		}
	default:
		return false
	}
	if key1.GetEncoding() != key2.GetEncoding() {
		// TODO: not necessarily
		return false
	}

	if key1.GetEncoding() == pb.KeyEncoding_KEY_ENCODING_UNSPECIFIED {
		return false
	}

	return bytes.Equal(key1.GetKeyData(), key2.GetKeyData())
}

func IsValidPublicKey(key *pb.PublicKey) (bool, error) {
	if key == nil {
		return false, errors.New("public key is nil")
	}

	if key.Algorithm == pb.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED {
		return false, errors.New("key algorithm is unspecified")
	}

	if err := validateKeyParams(key); err != nil {
		return false, err
	}

	if key.Encoding == pb.KeyEncoding_KEY_ENCODING_UNSPECIFIED {
		return false, errors.New("key encoding is unspecified")
	}

	if len(key.KeyData) == 0 {
		return false, errors.New("key data is empty")
	}

	parsed, err := parseAndVerifyKeyData(key)
	if err != nil {
		return false, fmt.Errorf("key data validation failed: %w", err)
	}

	if key.Certificate != nil {
		if err := verifyCertificateMatchesKey(key.Certificate, parsed); err != nil {
			return false, fmt.Errorf("certificate validation failed: %w", err)
		}
	}

	return true, nil
}

// validateKeyParams checks that the oneof key_params field matches the declared algorithm.
func validateKeyParams(key *pb.PublicKey) error {
	switch key.Algorithm {
	case pb.KeyAlgorithm_KEY_ALGORITHM_EC:
		curve := key.GetEllipticCurve()
		if curve == pb.EllipticCurve_ELLIPTIC_CURVE_UNSPECIFIED {
			return errors.New("EC algorithm requires an elliptic curve to be specified")
		}
		if key.GetRsaKeySize() != pb.RsaKeySize_RSA_KEY_SIZE_UNSPECIFIED {
			return errors.New("EC algorithm must not have RSA key size set")
		}
	case pb.KeyAlgorithm_KEY_ALGORITHM_RSA:
		size := key.GetRsaKeySize()
		if size == pb.RsaKeySize_RSA_KEY_SIZE_UNSPECIFIED {
			return errors.New("RSA algorithm requires a key size to be specified")
		}
		if key.GetEllipticCurve() != pb.EllipticCurve_ELLIPTIC_CURVE_UNSPECIFIED {
			return errors.New("RSA algorithm must not have elliptic curve set")
		}
	default:
		return fmt.Errorf("unsupported key algorithm: %v", key.Algorithm)
	}
	return nil
}

// parseAndVerifyKeyData parses the raw key bytes according to the declared encoding
// and verifies the parsed key matches the declared algorithm and parameters.
func parseAndVerifyKeyData(key *pb.PublicKey) (any, error) {
	if key.Encoding != pb.KeyEncoding_KEY_ENCODING_SPKI_DER {
		return nil, fmt.Errorf("unsupported key encoding: %v", key.Encoding)
	}

	parsed, err := x509.ParsePKIXPublicKey(key.KeyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SPKI DER key: %w", err)
	}

	switch key.Algorithm {
	case pb.KeyAlgorithm_KEY_ALGORITHM_EC:
		ecKey, ok := parsed.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("key data contains %T, expected *ecdsa.PublicKey", parsed)
		}
		if err := matchEllipticCurve(ecKey.Curve, key.GetEllipticCurve()); err != nil {
			return nil, err
		}
		return ecKey, nil

	case pb.KeyAlgorithm_KEY_ALGORITHM_RSA:
		rsaKey, ok := parsed.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("key data contains %T, expected *rsa.PublicKey", parsed)
		}
		if err := matchRsaKeySize(rsaKey.Size()*8, key.GetRsaKeySize()); err != nil {
			return nil, err
		}
		return rsaKey, nil

	default:
		return nil, fmt.Errorf("unsupported algorithm: %v", key.Algorithm)
	}
}

func matchEllipticCurve(actual elliptic.Curve, declared pb.EllipticCurve) error {
	expected, err := curveFromProto(declared)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("elliptic curve mismatch: key uses %v, declared %v", actual.Params().Name, declared)
	}
	return nil
}

func curveFromProto(c pb.EllipticCurve) (elliptic.Curve, error) {
	switch c {
	case pb.EllipticCurve_ELLIPTIC_CURVE_P256:
		return elliptic.P256(), nil
	case pb.EllipticCurve_ELLIPTIC_CURVE_P384:
		return elliptic.P384(), nil
	case pb.EllipticCurve_ELLIPTIC_CURVE_P521:
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported elliptic curve: %v", c)
	}
}

func matchRsaKeySize(actualBits int, declared pb.RsaKeySize) error {
	expectedBits, err := rsaBitsFromProto(declared)
	if err != nil {
		return err
	}
	if actualBits != expectedBits {
		return fmt.Errorf("RSA key size mismatch: key is %d bits, declared %v", actualBits, declared)
	}
	return nil
}

func rsaBitsFromProto(s pb.RsaKeySize) (int, error) {
	switch s {
	case pb.RsaKeySize_RSA_KEY_SIZE_2048:
		return 2048, nil
	case pb.RsaKeySize_RSA_KEY_SIZE_3072:
		return 3072, nil
	case pb.RsaKeySize_RSA_KEY_SIZE_4096:
		return 4096, nil
	default:
		return 0, fmt.Errorf("unsupported RSA key size: %v", s)
	}
}

// verifyCertificateMatchesKey parses the certificate and checks that its
// embedded public key is identical to the provided key.
func verifyCertificateMatchesKey(cert *pb.Certificate, pubKey any) error {
	if cert.Type == pb.CertificateType_CERTIFICATE_TYPE_UNSPECIFIED {
		return errors.New("certificate type is unspecified")
	}
	if cert.Type != pb.CertificateType_CERTIFICATE_TYPE_X509 {
		return fmt.Errorf("unsupported certificate type: %v", cert.Type)
	}
	if len(cert.Data) == 0 {
		return errors.New("certificate data is empty")
	}

	derBytes, err := extractCertDER(cert)
	if err != nil {
		return err
	}

	x509Cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return fmt.Errorf("failed to parse x509 certificate: %w", err)
	}

	if !publicKeysEqual(x509Cert.PublicKey, pubKey) {
		return errors.New("certificate public key does not match the provided public key")
	}

	return nil
}

func extractCertDER(cert *pb.Certificate) ([]byte, error) {
	switch cert.Encoding {
	case pb.CertificateEncoding_CERTIFICATE_ENCODING_DER:
		return cert.Data, nil

	case pb.CertificateEncoding_CERTIFICATE_ENCODING_PEM:
		block, _ := pem.Decode(cert.Data)
		if block == nil {
			return nil, errors.New("failed to decode PEM block from certificate data")
		}
		return block.Bytes, nil

	default:
		return nil, fmt.Errorf("unsupported certificate encoding: %v", cert.Encoding)
	}
}

func publicKeysEqual(a, b any) bool {
	switch aKey := a.(type) {
	case *ecdsa.PublicKey:
		bKey, ok := b.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		return aKey.Equal(bKey)
	case *rsa.PublicKey:
		bKey, ok := b.(*rsa.PublicKey)
		if !ok {
			return false
		}
		return aKey.Equal(bKey)
	default:
		return false
	}
}
