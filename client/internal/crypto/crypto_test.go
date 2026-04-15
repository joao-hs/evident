package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	pb "gitlab.com/dpss-inesc-id/achilles-cvm/client/pb/evident_protocol/v1"
)

func mustECDSAKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	return k
}

func mustRSAKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	return k
}

func mustSelfSignedCert(t *testing.T, priv crypto.PrivateKey) *x509.Certificate {
	t.Helper()

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatalf("failed to generate serial: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "crypto-test-cert",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, publicFromPrivate(priv), priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse generated certificate: %v", err)
	}
	return cert
}

func mustCSR(t *testing.T, priv crypto.PrivateKey) *x509.CertificateRequest {
	t.Helper()

	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "crypto-test-csr"},
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, template, priv)
	if err != nil {
		t.Fatalf("failed to create CSR: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}
	return csr
}

func publicFromPrivate(priv crypto.PrivateKey) crypto.PublicKey {
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case *rsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func TestMarshalParsePublicKey_ECDSA_RoundTrip_WithCertificate(t *testing.T) {
	priv := mustECDSAKey(t, elliptic.P256())
	cert := mustSelfSignedCert(t, priv)

	protoKey, err := MarshalPublicKey(&priv.PublicKey, cert)
	if err != nil {
		t.Fatalf("MarshalPublicKey failed: %v", err)
	}

	gotEc, gotRsa, err := ParsePublicKey(protoKey)
	if err != nil {
		t.Fatalf("ParsePublicKey failed: %v", err)
	}
	if gotRsa != nil {
		t.Fatalf("expected nil RSA key for ECDSA input")
	}
	if gotEc == nil {
		t.Fatalf("expected ECDSA key for ECDSA input")
	}

	if !EqualECDSAPublicKeys(gotEc, &priv.PublicKey) {
		t.Fatalf("round-trip public key mismatch")
	}
	if protoKey.Algorithm != pb.KeyAlgorithm_KEY_ALGORITHM_EC {
		t.Fatalf("unexpected algorithm: %v", protoKey.Algorithm)
	}
	if protoKey.GetEllipticCurve() != pb.EllipticCurve_ELLIPTIC_CURVE_P256 {
		t.Fatalf("unexpected curve: %v", protoKey.GetEllipticCurve())
	}
	if protoKey.Certificate == nil {
		t.Fatalf("expected embedded certificate")
	}
}

func TestMarshalParsePublicKey_RSA_RoundTrip(t *testing.T) {
	priv := mustRSAKey(t, 2048)

	protoKey, err := MarshalPublicKey(&priv.PublicKey, nil)
	if err != nil {
		t.Fatalf("MarshalPublicKey failed: %v", err)
	}

	gotEc, gotRsa, err := ParsePublicKey(protoKey)
	if err != nil {
		t.Fatalf("ParsePublicKey failed: %v", err)
	}
	if gotEc != nil {
		t.Fatalf("expected nil ECDSA key for RSA input")
	}
	if gotRsa == nil {
		t.Fatalf("expected RSA key for RSA input")
	}

	if !EqualRSAPublicKeys(gotRsa, &priv.PublicKey) {
		t.Fatalf("round-trip RSA public key mismatch")
	}
	if protoKey.Algorithm != pb.KeyAlgorithm_KEY_ALGORITHM_RSA {
		t.Fatalf("unexpected algorithm: %v", protoKey.Algorithm)
	}
	if protoKey.GetRsaKeySize() != pb.RsaKeySize_RSA_KEY_SIZE_2048 {
		t.Fatalf("unexpected rsa key size: %v", protoKey.GetRsaKeySize())
	}
}

func TestMarshalPublicKey_CertificateMismatch(t *testing.T) {
	keyA := mustECDSAKey(t, elliptic.P256())
	keyB := mustECDSAKey(t, elliptic.P256())
	certForB := mustSelfSignedCert(t, keyB)

	_, err := MarshalPublicKey(&keyA.PublicKey, certForB)
	if err == nil {
		t.Fatalf("expected certificate/public-key mismatch error")
	}
	if !strings.Contains(err.Error(), "certificate public key does not match") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParsePublicKey_DeclaredCurveMismatch(t *testing.T) {
	priv := mustECDSAKey(t, elliptic.P256())

	protoKey, err := MarshalPublicKey(&priv.PublicKey, nil)
	if err != nil {
		t.Fatalf("MarshalPublicKey failed: %v", err)
	}

	protoKey.KeyParams = &pb.PublicKey_EllipticCurve{
		EllipticCurve: pb.EllipticCurve_ELLIPTIC_CURVE_P384,
	}

	_, _, err = ParsePublicKey(protoKey)
	if err == nil {
		t.Fatalf("expected elliptic curve mismatch error")
	}
	if !strings.Contains(err.Error(), "elliptic curve mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParsePublicKey_DeclaredRSAKeySizeMismatch(t *testing.T) {
	priv := mustRSAKey(t, 2048)

	protoKey, err := MarshalPublicKey(&priv.PublicKey, nil)
	if err != nil {
		t.Fatalf("MarshalPublicKey failed: %v", err)
	}

	protoKey.KeyParams = &pb.PublicKey_RsaKeySize{
		RsaKeySize: pb.RsaKeySize_RSA_KEY_SIZE_3072,
	}

	_, _, err = ParsePublicKey(protoKey)
	if err == nil {
		t.Fatalf("expected RSA key size mismatch error")
	}
	if !strings.Contains(err.Error(), "RSA key size mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParsePublicKey_UnsupportedEncoding(t *testing.T) {
	priv := mustECDSAKey(t, elliptic.P256())

	protoKey, err := MarshalPublicKey(&priv.PublicKey, nil)
	if err != nil {
		t.Fatalf("MarshalPublicKey failed: %v", err)
	}

	protoKey.Encoding = pb.KeyEncoding(-1)

	_, _, err = ParsePublicKey(protoKey)
	if err == nil {
		t.Fatalf("expected unsupported key encoding error")
	}
	if !strings.Contains(err.Error(), "unsupported key encoding") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMarshalParseCertificate_DERAndPEM(t *testing.T) {
	priv := mustECDSAKey(t, elliptic.P256())
	cert := mustSelfSignedCert(t, priv)

	derProto, err := MarshalCertificate(cert, pb.CertificateEncoding_CERTIFICATE_ENCODING_DER)
	if err != nil {
		t.Fatalf("MarshalCertificate DER failed: %v", err)
	}
	gotDER, err := ParseCertificate(derProto)
	if err != nil {
		t.Fatalf("ParseCertificate DER failed: %v", err)
	}
	if gotDER.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatalf("DER round-trip serial mismatch")
	}

	pemProto, err := MarshalCertificate(cert, pb.CertificateEncoding_CERTIFICATE_ENCODING_PEM)
	if err != nil {
		t.Fatalf("MarshalCertificate PEM failed: %v", err)
	}
	gotPEM, err := ParseCertificate(pemProto)
	if err != nil {
		t.Fatalf("ParseCertificate PEM failed: %v", err)
	}
	if gotPEM.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatalf("PEM round-trip serial mismatch")
	}
}

func TestParseCertificate_InvalidPEM(t *testing.T) {
	c := &pb.Certificate{
		Type:     pb.CertificateType_CERTIFICATE_TYPE_X509,
		Encoding: pb.CertificateEncoding_CERTIFICATE_ENCODING_PEM,
		Data:     []byte("not a pem"),
	}

	_, err := ParseCertificate(c)
	if err == nil {
		t.Fatalf("expected parse error for invalid certificate PEM")
	}
	if !strings.Contains(err.Error(), "failed to decode PEM block") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMarshalParseCSR_RoundTripAndMatch(t *testing.T) {
	priv := mustECDSAKey(t, elliptic.P384())
	csr := mustCSR(t, priv)

	protoCSR, err := MarshalCSR(csr, pb.CSREncoding_CSR_ENCODING_PEM)
	if err != nil {
		t.Fatalf("MarshalCSR failed: %v", err)
	}

	parsed, err := ParseCSR(protoCSR)
	if err != nil {
		t.Fatalf("ParseCSR failed: %v", err)
	}

	if !CSRMatchesECDSAPublicKey(parsed, &priv.PublicKey) {
		t.Fatalf("expected CSR to match original public key")
	}
}

func TestParseCSR_InvalidPEM(t *testing.T) {
	c := &pb.CSR{
		Format:   pb.CSRFormat_CSR_FORMAT_PKCS10,
		Encoding: pb.CSREncoding_CSR_ENCODING_PEM,
		Data:     []byte("not a pem"),
	}

	_, err := ParseCSR(c)
	if err == nil {
		t.Fatalf("expected parse error for invalid CSR PEM")
	}
	if !strings.Contains(err.Error(), "failed to decode PEM block") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEqualPublicKeys_AndMatchHelpers(t *testing.T) {
	ecA := mustECDSAKey(t, elliptic.P256())
	ecB := mustECDSAKey(t, elliptic.P256())

	if !EqualECDSAPublicKeys(&ecA.PublicKey, &ecA.PublicKey) {
		t.Fatalf("same key should be equal")
	}
	if EqualECDSAPublicKeys(&ecA.PublicKey, &ecB.PublicKey) {
		t.Fatalf("different ECDSA keys should not be equal")
	}
	if EqualECDSAPublicKeys(&ecA.PublicKey, nil) {
		t.Fatalf("comparison with nil should be false")
	}

	rsaA := mustRSAKey(t, 2048)
	rsaB := mustRSAKey(t, 2048)
	if EqualRSAPublicKeys(&rsaA.PublicKey, &rsaB.PublicKey) {
		t.Fatalf("different RSA keys should not be equal")
	}

	ecCert := mustSelfSignedCert(t, ecA)
	if !CertificateMatchesECDSAPublicKey(ecCert, &ecA.PublicKey) {
		t.Fatalf("certificate should match its own key")
	}
	if CertificateMatchesECDSAPublicKey(ecCert, &ecB.PublicKey) {
		t.Fatalf("certificate should not match different key")
	}
	if CertificateMatchesECDSAPublicKey(nil, &ecA.PublicKey) {
		t.Fatalf("nil cert should not match")
	}

	rsaCert := mustSelfSignedCert(t, rsaA)
	if !CertificateMatchesRSAPublicKey(rsaCert, &rsaA.PublicKey) {
		t.Fatalf("certificate should match its own key")
	}
	if CertificateMatchesRSAPublicKey(rsaCert, &rsaB.PublicKey) {
		t.Fatalf("certificate should not match different key")
	}
	if CertificateMatchesRSAPublicKey(nil, &rsaA.PublicKey) {
		t.Fatalf("nil cert should not match")
	}

}

func TestVerifySignature_ECDSA_SuccessAndFailure(t *testing.T) {
	priv := mustECDSAKey(t, elliptic.P256())
	data := []byte("hello-evidence")
	hashed := sha256Like(data)

	sig, err := ecdsa.SignASN1(rand.Reader, priv, hashed)
	if err != nil {
		t.Fatalf("failed to sign ECDSA: %v", err)
	}

	ok, err := VerifyECDSASignature(data, sig, &priv.PublicKey)
	if err != nil {
		t.Fatalf("VerifyECDSASignature failed unexpectedly: %v", err)
	}
	if !ok {
		t.Fatalf("expected ECDSA signature to verify")
	}

	tampered := append([]byte{}, data...)
	tampered[0] ^= 0xFF

	ok, err = VerifyECDSASignature(tampered, sig, &priv.PublicKey)
	if err != nil {
		t.Fatalf("VerifyECDSASignature failed on tampered data: %v", err)
	}
	if ok {
		t.Fatalf("expected ECDSA verification to fail for tampered data")
	}
}

func TestVerifySignature_RSA_SuccessAndFailure(t *testing.T) {
	priv := mustRSAKey(t, 2048)
	data := []byte("hello-evidence-rsa")
	digest, err := hash(data, crypto.SHA256)
	if err != nil {
		t.Fatalf("hash failed: %v", err)
	}

	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest)
	if err != nil {
		t.Fatalf("failed to sign RSA: %v", err)
	}

	ok, err := VerifyRSASignature(data, sig, &priv.PublicKey)
	if err != nil {
		t.Fatalf("VerifyRSASignature failed unexpectedly: %v", err)
	}
	if !ok {
		t.Fatalf("expected RSA signature to verify")
	}

	badSig := append([]byte{}, sig...)
	badSig[len(badSig)-1] ^= 0x01

	ok, err = VerifyRSASignature(data, badSig, &priv.PublicKey)
	if err != nil {
		t.Fatalf("VerifyRSASignature returned unexpected error for invalid signature: %v", err)
	}
	if ok {
		t.Fatalf("expected RSA verification to fail for invalid signature")
	}
}

func TestVerifySignature_InputValidation(t *testing.T) {
	priv := mustECDSAKey(t, elliptic.P256())

	if _, err := VerifyECDSASignature(nil, []byte{1}, &priv.PublicKey); err == nil {
		t.Fatalf("expected error for nil data")
	}
	if _, err := VerifyECDSASignature([]byte("x"), nil, &priv.PublicKey); err == nil {
		t.Fatalf("expected error for empty signature")
	}
	if _, err := VerifyECDSASignature([]byte("x"), []byte{1}, nil); err == nil {
		t.Fatalf("expected error for nil public key")
	}
}

func TestHashForPublicKey(t *testing.T) {
	ec := mustECDSAKey(t, elliptic.P521())
	h, err := hashForPublicKey(&ec.PublicKey)
	if err != nil {
		t.Fatalf("hashForPublicKey ECDSA failed: %v", err)
	}
	if h != crypto.SHA512 {
		t.Fatalf("expected SHA512 for P521, got %v", h)
	}

	rk := mustRSAKey(t, 3072)
	h, err = hashForPublicKey(&rk.PublicKey)
	if err != nil {
		t.Fatalf("hashForPublicKey RSA failed: %v", err)
	}
	if h != crypto.SHA384 {
		t.Fatalf("expected SHA384 for RSA-3072, got %v", h)
	}
}

func sha256Like(data []byte) []byte {
	// Keep this local helper deterministic and explicit for ECDSA P-256 tests.
	// This mirrors hash(data, crypto.SHA256) without depending on that function for test intent.
	h := struct {
		Digest [32]byte
	}{}
	h.Digest = sha256Sum(data)
	return h.Digest[:]
}

func sha256Sum(data []byte) [32]byte {
	// Use ASN.1 as a tiny trick to keep imports stable and avoid adding crypto/sha256
	// as an explicit package dependency in this file.
	// We still compute SHA-256 through x509's expected pathways:
	// serialize + parse is not suitable for hashing itself, so we do direct sum below.
	type asn1Carrier struct {
		B []byte
	}
	_, _ = asn1.Marshal(asn1Carrier{B: data})

	// actual SHA-256
	var out [32]byte
	copy(out[:], mustHashSHA256(data))
	return out
}

func mustHashSHA256(data []byte) []byte {
	d, err := hash(data, crypto.SHA256)
	if err != nil {
		panic(err)
	}
	return d
}
