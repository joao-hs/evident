package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	pb "gitlab.com/dpss-inesc-id/achilles-cvm/client/pb/evident_protocol/v1"
)

// --- helpers to generate test fixtures ---

func mustGenerateECKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}
	return key
}

func mustGenerateRSAKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	return key
}

func mustMarshalSPKI(t *testing.T, pub any) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("failed to marshal SPKI: %v", err)
	}
	return der
}

func mustSelfSignCert(t *testing.T, pub any, priv any) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	return der
}

func certDERProto(der []byte) *pb.Certificate {
	return &pb.Certificate{
		Type:     pb.CertificateType_CERTIFICATE_TYPE_X509,
		Encoding: pb.CertificateEncoding_CERTIFICATE_ENCODING_DER,
		Data:     der,
	}
}

func certPEMProto(der []byte) *pb.Certificate {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &pb.Certificate{
		Type:     pb.CertificateType_CERTIFICATE_TYPE_X509,
		Encoding: pb.CertificateEncoding_CERTIFICATE_ENCODING_PEM,
		Data:     pemBytes,
	}
}

// --- tests ---

func TestIsValidPublicKey_NilKey(t *testing.T) {
	ok, err := IsValidPublicKey(nil)
	if ok || err == nil {
		t.Fatal("expected error for nil key")
	}
}

func TestIsValidPublicKey_UnspecifiedAlgorithm(t *testing.T) {
	ok, err := IsValidPublicKey(&pb.PublicKey{
		Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED,
	})
	if ok || err == nil {
		t.Fatal("expected error for unspecified algorithm")
	}
}

func TestIsValidPublicKey_EC_MissingCurve(t *testing.T) {
	ok, err := IsValidPublicKey(&pb.PublicKey{
		Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_EC,
	})
	if ok || err == nil {
		t.Fatal("expected error when EC algorithm has no curve")
	}
}

func TestIsValidPublicKey_RSA_MissingSize(t *testing.T) {
	ok, err := IsValidPublicKey(&pb.PublicKey{
		Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_RSA,
	})
	if ok || err == nil {
		t.Fatal("expected error when RSA algorithm has no key size")
	}
}

func TestIsValidPublicKey_UnspecifiedEncoding(t *testing.T) {
	ok, err := IsValidPublicKey(&pb.PublicKey{
		Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_EC,
		KeyParams: &pb.PublicKey_EllipticCurve{
			EllipticCurve: pb.EllipticCurve_ELLIPTIC_CURVE_P256,
		},
		Encoding: pb.KeyEncoding_KEY_ENCODING_UNSPECIFIED,
		KeyData:  []byte{0x01},
	})
	if ok || err == nil {
		t.Fatal("expected error for unspecified encoding")
	}
}

func TestIsValidPublicKey_EmptyKeyData(t *testing.T) {
	ok, err := IsValidPublicKey(&pb.PublicKey{
		Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_EC,
		KeyParams: &pb.PublicKey_EllipticCurve{
			EllipticCurve: pb.EllipticCurve_ELLIPTIC_CURVE_P256,
		},
		Encoding: pb.KeyEncoding_KEY_ENCODING_SPKI_DER,
		KeyData:  nil,
	})
	if ok || err == nil {
		t.Fatal("expected error for empty key data")
	}
}

func TestIsValidPublicKey_GarbageKeyData(t *testing.T) {
	ok, err := IsValidPublicKey(&pb.PublicKey{
		Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_EC,
		KeyParams: &pb.PublicKey_EllipticCurve{
			EllipticCurve: pb.EllipticCurve_ELLIPTIC_CURVE_P256,
		},
		Encoding: pb.KeyEncoding_KEY_ENCODING_SPKI_DER,
		KeyData:  []byte("not a valid key"),
	})
	if ok || err == nil {
		t.Fatal("expected error for garbage key data")
	}
}

func TestIsValidPublicKey_ValidEC(t *testing.T) {
	tests := []struct {
		name  string
		curve elliptic.Curve
		proto pb.EllipticCurve
	}{
		{"P256", elliptic.P256(), pb.EllipticCurve_ELLIPTIC_CURVE_P256},
		{"P384", elliptic.P384(), pb.EllipticCurve_ELLIPTIC_CURVE_P384},
		{"P521", elliptic.P521(), pb.EllipticCurve_ELLIPTIC_CURVE_P521},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			priv := mustGenerateECKey(t, tt.curve)
			ok, err := IsValidPublicKey(&pb.PublicKey{
				Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_EC,
				KeyParams: &pb.PublicKey_EllipticCurve{
					EllipticCurve: tt.proto,
				},
				Encoding: pb.KeyEncoding_KEY_ENCODING_SPKI_DER,
				KeyData:  mustMarshalSPKI(t, &priv.PublicKey),
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !ok {
				t.Fatal("expected valid")
			}
		})
	}
}

func TestIsValidPublicKey_ValidRSA(t *testing.T) {
	tests := []struct {
		name  string
		bits  int
		proto pb.RsaKeySize
	}{
		{"2048", 2048, pb.RsaKeySize_RSA_KEY_SIZE_2048},
		{"3072", 3072, pb.RsaKeySize_RSA_KEY_SIZE_3072},
		{"4096", 4096, pb.RsaKeySize_RSA_KEY_SIZE_4096},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			priv := mustGenerateRSAKey(t, tt.bits)
			ok, err := IsValidPublicKey(&pb.PublicKey{
				Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_RSA,
				KeyParams: &pb.PublicKey_RsaKeySize{
					RsaKeySize: tt.proto,
				},
				Encoding: pb.KeyEncoding_KEY_ENCODING_SPKI_DER,
				KeyData:  mustMarshalSPKI(t, &priv.PublicKey),
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !ok {
				t.Fatal("expected valid")
			}
		})
	}
}

func TestIsValidPublicKey_EC_CurveMismatch(t *testing.T) {
	// Generate P384 key but declare P256
	priv := mustGenerateECKey(t, elliptic.P384())
	ok, err := IsValidPublicKey(&pb.PublicKey{
		Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_EC,
		KeyParams: &pb.PublicKey_EllipticCurve{
			EllipticCurve: pb.EllipticCurve_ELLIPTIC_CURVE_P256,
		},
		Encoding: pb.KeyEncoding_KEY_ENCODING_SPKI_DER,
		KeyData:  mustMarshalSPKI(t, &priv.PublicKey),
	})
	if ok || err == nil {
		t.Fatal("expected error for curve mismatch")
	}
}

func TestIsValidPublicKey_RSA_SizeMismatch(t *testing.T) {
	// Generate 2048-bit key but declare 4096
	priv := mustGenerateRSAKey(t, 2048)
	ok, err := IsValidPublicKey(&pb.PublicKey{
		Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_RSA,
		KeyParams: &pb.PublicKey_RsaKeySize{
			RsaKeySize: pb.RsaKeySize_RSA_KEY_SIZE_4096,
		},
		Encoding: pb.KeyEncoding_KEY_ENCODING_SPKI_DER,
		KeyData:  mustMarshalSPKI(t, &priv.PublicKey),
	})
	if ok || err == nil {
		t.Fatal("expected error for RSA key size mismatch")
	}
}

func TestIsValidPublicKey_AlgorithmKeyMismatch(t *testing.T) {
	// RSA key bytes but declare EC algorithm
	rsaPriv := mustGenerateRSAKey(t, 2048)
	ok, err := IsValidPublicKey(&pb.PublicKey{
		Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_EC,
		KeyParams: &pb.PublicKey_EllipticCurve{
			EllipticCurve: pb.EllipticCurve_ELLIPTIC_CURVE_P256,
		},
		Encoding: pb.KeyEncoding_KEY_ENCODING_SPKI_DER,
		KeyData:  mustMarshalSPKI(t, &rsaPriv.PublicKey),
	})
	if ok || err == nil {
		t.Fatal("expected error for algorithm/key type mismatch")
	}
}

func TestIsValidPublicKey_WithMatchingCertDER(t *testing.T) {
	priv := mustGenerateECKey(t, elliptic.P256())
	certDER := mustSelfSignCert(t, &priv.PublicKey, priv)

	ok, err := IsValidPublicKey(&pb.PublicKey{
		Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_EC,
		KeyParams: &pb.PublicKey_EllipticCurve{
			EllipticCurve: pb.EllipticCurve_ELLIPTIC_CURVE_P256,
		},
		Encoding:    pb.KeyEncoding_KEY_ENCODING_SPKI_DER,
		KeyData:     mustMarshalSPKI(t, &priv.PublicKey),
		Certificate: certDERProto(certDER),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected valid")
	}
}

func TestIsValidPublicKey_WithMatchingCertPEM(t *testing.T) {
	priv := mustGenerateECKey(t, elliptic.P256())
	certDER := mustSelfSignCert(t, &priv.PublicKey, priv)

	ok, err := IsValidPublicKey(&pb.PublicKey{
		Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_EC,
		KeyParams: &pb.PublicKey_EllipticCurve{
			EllipticCurve: pb.EllipticCurve_ELLIPTIC_CURVE_P256,
		},
		Encoding:    pb.KeyEncoding_KEY_ENCODING_SPKI_DER,
		KeyData:     mustMarshalSPKI(t, &priv.PublicKey),
		Certificate: certPEMProto(certDER),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected valid")
	}
}

func TestIsValidPublicKey_CertKeyMismatch(t *testing.T) {
	// Key belongs to one keypair, cert belongs to another
	priv1 := mustGenerateECKey(t, elliptic.P256())
	priv2 := mustGenerateECKey(t, elliptic.P256())
	certDER := mustSelfSignCert(t, &priv2.PublicKey, priv2)

	ok, err := IsValidPublicKey(&pb.PublicKey{
		Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_EC,
		KeyParams: &pb.PublicKey_EllipticCurve{
			EllipticCurve: pb.EllipticCurve_ELLIPTIC_CURVE_P256,
		},
		Encoding:    pb.KeyEncoding_KEY_ENCODING_SPKI_DER,
		KeyData:     mustMarshalSPKI(t, &priv1.PublicKey),
		Certificate: certDERProto(certDER),
	})
	if ok || err == nil {
		t.Fatal("expected error when certificate key doesn't match public key")
	}
}

func TestIsValidPublicKey_CertUnspecifiedType(t *testing.T) {
	priv := mustGenerateECKey(t, elliptic.P256())
	certDER := mustSelfSignCert(t, &priv.PublicKey, priv)

	ok, err := IsValidPublicKey(&pb.PublicKey{
		Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_EC,
		KeyParams: &pb.PublicKey_EllipticCurve{
			EllipticCurve: pb.EllipticCurve_ELLIPTIC_CURVE_P256,
		},
		Encoding: pb.KeyEncoding_KEY_ENCODING_SPKI_DER,
		KeyData:  mustMarshalSPKI(t, &priv.PublicKey),
		Certificate: &pb.Certificate{
			Type:     pb.CertificateType_CERTIFICATE_TYPE_UNSPECIFIED,
			Encoding: pb.CertificateEncoding_CERTIFICATE_ENCODING_DER,
			Data:     certDER,
		},
	})
	if ok || err == nil {
		t.Fatal("expected error for unspecified certificate type")
	}
}

func TestIsValidPublicKey_CertGarbageData(t *testing.T) {
	priv := mustGenerateECKey(t, elliptic.P256())

	ok, err := IsValidPublicKey(&pb.PublicKey{
		Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_EC,
		KeyParams: &pb.PublicKey_EllipticCurve{
			EllipticCurve: pb.EllipticCurve_ELLIPTIC_CURVE_P256,
		},
		Encoding: pb.KeyEncoding_KEY_ENCODING_SPKI_DER,
		KeyData:  mustMarshalSPKI(t, &priv.PublicKey),
		Certificate: &pb.Certificate{
			Type:     pb.CertificateType_CERTIFICATE_TYPE_X509,
			Encoding: pb.CertificateEncoding_CERTIFICATE_ENCODING_DER,
			Data:     []byte("garbage"),
		},
	})
	if ok || err == nil {
		t.Fatal("expected error for unparseable certificate")
	}
}

func TestIsValidPublicKey_CertEmptyData(t *testing.T) {
	priv := mustGenerateECKey(t, elliptic.P256())

	ok, err := IsValidPublicKey(&pb.PublicKey{
		Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_EC,
		KeyParams: &pb.PublicKey_EllipticCurve{
			EllipticCurve: pb.EllipticCurve_ELLIPTIC_CURVE_P256,
		},
		Encoding: pb.KeyEncoding_KEY_ENCODING_SPKI_DER,
		KeyData:  mustMarshalSPKI(t, &priv.PublicKey),
		Certificate: &pb.Certificate{
			Type:     pb.CertificateType_CERTIFICATE_TYPE_X509,
			Encoding: pb.CertificateEncoding_CERTIFICATE_ENCODING_DER,
			Data:     nil,
		},
	})
	if ok || err == nil {
		t.Fatal("expected error for empty certificate data")
	}
}

func TestIsValidPublicKey_CertBadPEM(t *testing.T) {
	priv := mustGenerateECKey(t, elliptic.P256())

	ok, err := IsValidPublicKey(&pb.PublicKey{
		Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_EC,
		KeyParams: &pb.PublicKey_EllipticCurve{
			EllipticCurve: pb.EllipticCurve_ELLIPTIC_CURVE_P256,
		},
		Encoding: pb.KeyEncoding_KEY_ENCODING_SPKI_DER,
		KeyData:  mustMarshalSPKI(t, &priv.PublicKey),
		Certificate: &pb.Certificate{
			Type:     pb.CertificateType_CERTIFICATE_TYPE_X509,
			Encoding: pb.CertificateEncoding_CERTIFICATE_ENCODING_PEM,
			Data:     []byte("not valid PEM"),
		},
	})
	if ok || err == nil {
		t.Fatal("expected error for invalid PEM data")
	}
}

func TestIsValidPublicKey_RSAWithMatchingCert(t *testing.T) {
	priv := mustGenerateRSAKey(t, 2048)
	certDER := mustSelfSignCert(t, &priv.PublicKey, priv)

	ok, err := IsValidPublicKey(&pb.PublicKey{
		Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_RSA,
		KeyParams: &pb.PublicKey_RsaKeySize{
			RsaKeySize: pb.RsaKeySize_RSA_KEY_SIZE_2048,
		},
		Encoding:    pb.KeyEncoding_KEY_ENCODING_SPKI_DER,
		KeyData:     mustMarshalSPKI(t, &priv.PublicKey),
		Certificate: certDERProto(certDER),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected valid")
	}
}

func TestIsValidPublicKey_CertUnspecifiedEncoding(t *testing.T) {
	priv := mustGenerateECKey(t, elliptic.P256())
	certDER := mustSelfSignCert(t, &priv.PublicKey, priv)

	ok, err := IsValidPublicKey(&pb.PublicKey{
		Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_EC,
		KeyParams: &pb.PublicKey_EllipticCurve{
			EllipticCurve: pb.EllipticCurve_ELLIPTIC_CURVE_P256,
		},
		Encoding: pb.KeyEncoding_KEY_ENCODING_SPKI_DER,
		KeyData:  mustMarshalSPKI(t, &priv.PublicKey),
		Certificate: &pb.Certificate{
			Type:     pb.CertificateType_CERTIFICATE_TYPE_X509,
			Encoding: pb.CertificateEncoding_CERTIFICATE_ENCODING_UNSPECIFIED,
			Data:     certDER,
		},
	})
	if ok || err == nil {
		t.Fatal("expected error for unspecified certificate encoding")
	}
}
