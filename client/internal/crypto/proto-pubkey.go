package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	pb "gitlab.com/dpss-inesc-id/achilles-cvm/client/pb/evident_protocol/v1"
)

// ParseECDSAPublicKey converts a proto PublicKey into *ecdsa.PublicKey.
//
// It validates all proto fields internally, parses key material, and enforces that:
//   - declared algorithm/params match key_data
//   - if certificate is present, certificate public key matches key_data
func ParseECDSAPublicKey(key *pb.PublicKey) (*ecdsa.PublicKey, error) {
	if err := validateProtoPublicKey(key); err != nil {
		return nil, err
	}
	if key.Algorithm != pb.KeyAlgorithm_KEY_ALGORITHM_EC {
		return nil, fmt.Errorf("unexpected key algorithm for ECDSA parser: %v", key.Algorithm)
	}
	if key.Encoding != pb.KeyEncoding_KEY_ENCODING_SPKI_DER {
		return nil, fmt.Errorf("unsupported key encoding: %v", key.Encoding)
	}

	parsed, err := x509.ParsePKIXPublicKey(key.KeyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SPKI DER public key: %w", err)
	}

	ecKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key data contains %T, expected *ecdsa.PublicKey", parsed)
	}
	if err := matchEllipticCurve(ecKey.Curve, key.GetEllipticCurve()); err != nil {
		return nil, err
	}

	if key.Certificate != nil {
		cert, err := ParseCertificate(key.Certificate)
		if err != nil {
			return nil, fmt.Errorf("certificate validation failed: %w", err)
		}
		if !CertificateMatchesECDSAPublicKey(cert, ecKey) {
			return nil, errors.New("certificate public key does not match the provided public key")
		}
	}

	return ecKey, nil
}

// ParseRSAPublicKey converts a proto PublicKey into *rsa.PublicKey.
//
// It validates all proto fields internally, parses key material, and enforces that:
//   - declared algorithm/params match key_data
//   - if certificate is present, certificate public key matches key_data
func ParseRSAPublicKey(key *pb.PublicKey) (*rsa.PublicKey, error) {
	if err := validateProtoPublicKey(key); err != nil {
		return nil, err
	}
	if key.Algorithm != pb.KeyAlgorithm_KEY_ALGORITHM_RSA {
		return nil, fmt.Errorf("unexpected key algorithm for RSA parser: %v", key.Algorithm)
	}
	if key.Encoding != pb.KeyEncoding_KEY_ENCODING_SPKI_DER {
		return nil, fmt.Errorf("unsupported key encoding: %v", key.Encoding)
	}

	parsed, err := x509.ParsePKIXPublicKey(key.KeyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SPKI DER public key: %w", err)
	}

	rsaKey, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key data contains %T, expected *rsa.PublicKey", parsed)
	}
	if err := matchRsaKeySize(rsaKey.Size()*8, key.GetRsaKeySize()); err != nil {
		return nil, err
	}

	if key.Certificate != nil {
		cert, err := ParseCertificate(key.Certificate)
		if err != nil {
			return nil, fmt.Errorf("certificate validation failed: %w", err)
		}
		if !CertificateMatchesRSAPublicKey(cert, rsaKey) {
			return nil, errors.New("certificate public key does not match the provided public key")
		}
	}

	return rsaKey, nil
}

// ParsePublicKey dispatches to typed public key parsers based on declared algorithm.
// It validates all proto fields internally, parses key material, and enforces that:
//   - declared algorithm/params match key_data
//   - if certificate is present, certificate public key matches key_data
func ParsePublicKey(key *pb.PublicKey) (*ecdsa.PublicKey, *rsa.PublicKey, error) {
	if key == nil {
		return nil, nil, errors.New("public key is nil")
	}
	switch key.Algorithm {
	case pb.KeyAlgorithm_KEY_ALGORITHM_EC:
		ecPub, err := ParseECDSAPublicKey(key)
		return ecPub, nil, err
	case pb.KeyAlgorithm_KEY_ALGORITHM_RSA:
		rsaPub, err := ParseRSAPublicKey(key)
		return nil, rsaPub, err
	default:
		return nil, nil, fmt.Errorf("unsupported algorithm: %v", key.Algorithm)
	}
}

// MarshalECDSAPublicKey converts *ecdsa.PublicKey into proto PublicKey.
//
// If cert is non-nil, it is attached and must reference the same public key.
func MarshalECDSAPublicKey(pub *ecdsa.PublicKey, cert *x509.Certificate) (*pb.PublicKey, error) {
	if pub == nil {
		return nil, errors.New("public key is nil")
	}

	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SPKI DER public key: %w", err)
	}

	curve, err := curveToProto(pub.Curve)
	if err != nil {
		return nil, err
	}

	out := &pb.PublicKey{
		Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_EC,
		Encoding:  pb.KeyEncoding_KEY_ENCODING_SPKI_DER,
		KeyData:   spki,
		KeyParams: &pb.PublicKey_EllipticCurve{EllipticCurve: curve},
	}

	if cert != nil {
		if !CertificateMatchesECDSAPublicKey(cert, pub) {
			return nil, errors.New("certificate public key does not match provided public key")
		}
		protoCert, err := MarshalCertificate(cert, pb.CertificateEncoding_CERTIFICATE_ENCODING_DER)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal certificate: %w", err)
		}
		out.Certificate = protoCert
	}

	return out, nil
}

// MarshalRSAPublicKey converts *rsa.PublicKey into proto PublicKey.
//
// If cert is non-nil, it is attached and must reference the same public key.
func MarshalRSAPublicKey(pub *rsa.PublicKey, cert *x509.Certificate) (*pb.PublicKey, error) {
	if pub == nil {
		return nil, errors.New("public key is nil")
	}

	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SPKI DER public key: %w", err)
	}

	size, err := rsaBitsToProto(pub.Size() * 8)
	if err != nil {
		return nil, err
	}

	out := &pb.PublicKey{
		Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_RSA,
		Encoding:  pb.KeyEncoding_KEY_ENCODING_SPKI_DER,
		KeyData:   spki,
		KeyParams: &pb.PublicKey_RsaKeySize{RsaKeySize: size},
	}

	if cert != nil {
		if !CertificateMatchesRSAPublicKey(cert, pub) {
			return nil, errors.New("certificate public key does not match provided public key")
		}
		protoCert, err := MarshalCertificate(cert, pb.CertificateEncoding_CERTIFICATE_ENCODING_DER)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal certificate: %w", err)
		}
		out.Certificate = protoCert
	}

	return out, nil
}

// MarshalPublicKey marshals either *ecdsa.PublicKey or *rsa.PublicKey to proto PublicKey.
func MarshalPublicKey(pub any, cert *x509.Certificate) (*pb.PublicKey, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return MarshalECDSAPublicKey(k, cert)
	case *rsa.PublicKey:
		return MarshalRSAPublicKey(k, cert)
	case nil:
		return nil, errors.New("public key is nil")
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", pub)
	}
}

// ParseCertificate converts proto Certificate into *x509.Certificate.
func ParseCertificate(cert *pb.Certificate) (*x509.Certificate, error) {
	if err := validateProtoCertificate(cert); err != nil {
		return nil, err
	}

	derBytes, err := certificateDER(cert)
	if err != nil {
		return nil, err
	}

	x509Cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse x509 certificate: %w", err)
	}
	return x509Cert, nil
}

// MarshalCertificate converts *x509.Certificate into proto Certificate.
func MarshalCertificate(cert *x509.Certificate, enc pb.CertificateEncoding) (*pb.Certificate, error) {
	if cert == nil {
		return nil, errors.New("certificate is nil")
	}

	out := &pb.Certificate{
		Type: pb.CertificateType_CERTIFICATE_TYPE_X509,
	}

	switch enc {
	case pb.CertificateEncoding_CERTIFICATE_ENCODING_DER:
		out.Encoding = pb.CertificateEncoding_CERTIFICATE_ENCODING_DER
		out.Data = cert.Raw
	case pb.CertificateEncoding_CERTIFICATE_ENCODING_PEM:
		out.Encoding = pb.CertificateEncoding_CERTIFICATE_ENCODING_PEM
		out.Data = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	default:
		return nil, fmt.Errorf("unsupported certificate encoding: %v", enc)
	}

	return out, nil
}

// ParseCSR converts proto CSR into *x509.CertificateRequest and verifies its signature.
func ParseCSR(csr *pb.CSR) (*x509.CertificateRequest, error) {
	if err := validateProtoCSR(csr); err != nil {
		return nil, err
	}

	derBytes, err := csrDER(csr)
	if err != nil {
		return nil, err
	}

	cr, err := x509.ParseCertificateRequest(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#10 CSR: %w", err)
	}
	if err := cr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature verification failed: %w", err)
	}

	return cr, nil
}

// MarshalCSR converts *x509.CertificateRequest into proto CSR.
func MarshalCSR(csr *x509.CertificateRequest, enc pb.CSREncoding) (*pb.CSR, error) {
	if csr == nil {
		return nil, errors.New("CSR is nil")
	}
	if len(csr.Raw) == 0 {
		return nil, errors.New("CSR raw data is empty")
	}

	out := &pb.CSR{
		Format: pb.CSRFormat_CSR_FORMAT_PKCS10,
	}

	switch enc {
	case pb.CSREncoding_CSR_ENCODING_PEM:
		out.Encoding = pb.CSREncoding_CSR_ENCODING_PEM
		out.Data = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
	default:
		return nil, fmt.Errorf("unsupported CSR encoding: %v", enc)
	}

	return out, nil
}

// EqualECDSAPublicKeys compares ECDSA public keys for semantic equality.
func EqualECDSAPublicKeys(a, b *ecdsa.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Equal(b)
}

// EqualRSAPublicKeys compares RSA public keys for semantic equality.
func EqualRSAPublicKeys(a, b *rsa.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Equal(b)
}

// CSRMatchesECDSAPublicKey reports whether CSR embeds the provided ECDSA public key.
func CSRMatchesECDSAPublicKey(csr *x509.CertificateRequest, key *ecdsa.PublicKey) bool {
	if csr == nil || key == nil {
		return false
	}
	csrKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	return ok && EqualECDSAPublicKeys(csrKey, key)
}

// CSRMatchesRSAPublicKey reports whether CSR embeds the provided RSA public key.
func CSRMatchesRSAPublicKey(csr *x509.CertificateRequest, key *rsa.PublicKey) bool {
	if csr == nil || key == nil {
		return false
	}
	csrKey, ok := csr.PublicKey.(*rsa.PublicKey)
	return ok && EqualRSAPublicKeys(csrKey, key)
}

// CSRMatchesCertificate reports whether CSR embeds the same public key as the certificate.
func CSRMatchesCertificate(csr *x509.CertificateRequest, cert *x509.Certificate) bool {
	if csr == nil || cert == nil {
		return false
	}
	if csr.PublicKeyAlgorithm != cert.PublicKeyAlgorithm {
		return false
	}

	switch csr.PublicKeyAlgorithm {
	case x509.ECDSA:
		csrKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		certKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		return EqualECDSAPublicKeys(csrKey, certKey)
	case x509.RSA:
		csrKey, ok := csr.PublicKey.(*rsa.PublicKey)
		if !ok {
			return false
		}
		certKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return false
		}
		return EqualRSAPublicKeys(csrKey, certKey)
	default:
		return false
	}
}

// CertificateMatchesECDSAPublicKey reports whether certificate embeds the provided ECDSA public key.
func CertificateMatchesECDSAPublicKey(cert *x509.Certificate, key *ecdsa.PublicKey) bool {
	if cert == nil || key == nil {
		return false
	}
	certKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	return ok && EqualECDSAPublicKeys(certKey, key)
}

// CertificateMatchesRSAPublicKey reports whether certificate embeds the provided RSA public key.
func CertificateMatchesRSAPublicKey(cert *x509.Certificate, key *rsa.PublicKey) bool {
	if cert == nil || key == nil {
		return false
	}
	certKey, ok := cert.PublicKey.(*rsa.PublicKey)
	return ok && EqualRSAPublicKeys(certKey, key)
}

// ---------- internal validation / parsing helpers ----------

func validateProtoPublicKey(key *pb.PublicKey) error {
	if key == nil {
		return errors.New("public key is nil")
	}
	if key.Algorithm == pb.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED {
		return errors.New("key algorithm is unspecified")
	}
	if err := validateProtoKeyParams(key); err != nil {
		return err
	}
	if key.Encoding == pb.KeyEncoding_KEY_ENCODING_UNSPECIFIED {
		return errors.New("key encoding is unspecified")
	}
	if len(key.KeyData) == 0 {
		return errors.New("key data is empty")
	}
	return nil
}

func validateProtoKeyParams(key *pb.PublicKey) error {
	switch key.Algorithm {
	case pb.KeyAlgorithm_KEY_ALGORITHM_EC:
		if key.GetEllipticCurve() == pb.EllipticCurve_ELLIPTIC_CURVE_UNSPECIFIED {
			return errors.New("EC algorithm requires an elliptic curve to be specified")
		}
		if key.GetRsaKeySize() != pb.RsaKeySize_RSA_KEY_SIZE_UNSPECIFIED {
			return errors.New("EC algorithm must not have RSA key size set")
		}
	case pb.KeyAlgorithm_KEY_ALGORITHM_RSA:
		if key.GetRsaKeySize() == pb.RsaKeySize_RSA_KEY_SIZE_UNSPECIFIED {
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

func validateProtoCertificate(cert *pb.Certificate) error {
	if cert == nil {
		return errors.New("certificate is nil")
	}
	if cert.Type == pb.CertificateType_CERTIFICATE_TYPE_UNSPECIFIED {
		return errors.New("certificate type is unspecified")
	}
	if cert.Type != pb.CertificateType_CERTIFICATE_TYPE_X509 {
		return fmt.Errorf("unsupported certificate type: %v", cert.Type)
	}
	if cert.Encoding == pb.CertificateEncoding_CERTIFICATE_ENCODING_UNSPECIFIED {
		return errors.New("certificate encoding is unspecified")
	}
	if len(cert.Data) == 0 {
		return errors.New("certificate data is empty")
	}
	return nil
}

func validateProtoCSR(csr *pb.CSR) error {
	if csr == nil {
		return errors.New("CSR is nil")
	}
	if csr.Format == pb.CSRFormat_CSR_FORMAT_UNSPECIFIED {
		return errors.New("CSR format is unspecified")
	}
	if csr.Format != pb.CSRFormat_CSR_FORMAT_PKCS10 {
		return fmt.Errorf("unsupported CSR format: %v", csr.Format)
	}
	if csr.Encoding == pb.CSREncoding_CSR_ENCODING_UNSPECIFIED {
		return errors.New("CSR encoding is unspecified")
	}
	if len(csr.Data) == 0 {
		return errors.New("CSR data is empty")
	}
	return nil
}

func certificateDER(cert *pb.Certificate) ([]byte, error) {
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

func csrDER(csr *pb.CSR) ([]byte, error) {
	switch csr.Encoding {
	case pb.CSREncoding_CSR_ENCODING_PEM:
		block, _ := pem.Decode(csr.Data)
		if block == nil {
			return nil, errors.New("failed to decode PEM block from CSR data")
		}
		return block.Bytes, nil
	default:
		return nil, fmt.Errorf("unsupported CSR encoding: %v", csr.Encoding)
	}
}

func matchEllipticCurve(actual elliptic.Curve, declared pb.EllipticCurve) error {
	expected, err := curveFromProto(declared)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("elliptic curve mismatch: key uses %s, declared %v", actual.Params().Name, declared)
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

func curveToProto(c elliptic.Curve) (pb.EllipticCurve, error) {
	switch c {
	case elliptic.P256():
		return pb.EllipticCurve_ELLIPTIC_CURVE_P256, nil
	case elliptic.P384():
		return pb.EllipticCurve_ELLIPTIC_CURVE_P384, nil
	case elliptic.P521():
		return pb.EllipticCurve_ELLIPTIC_CURVE_P521, nil
	default:
		return pb.EllipticCurve_ELLIPTIC_CURVE_UNSPECIFIED, fmt.Errorf("unsupported elliptic curve: %T", c)
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

func rsaBitsToProto(bits int) (pb.RsaKeySize, error) {
	switch bits {
	case 2048:
		return pb.RsaKeySize_RSA_KEY_SIZE_2048, nil
	case 3072:
		return pb.RsaKeySize_RSA_KEY_SIZE_3072, nil
	case 4096:
		return pb.RsaKeySize_RSA_KEY_SIZE_4096, nil
	default:
		return pb.RsaKeySize_RSA_KEY_SIZE_UNSPECIFIED, fmt.Errorf("unsupported RSA key size: %d", bits)
	}
}
