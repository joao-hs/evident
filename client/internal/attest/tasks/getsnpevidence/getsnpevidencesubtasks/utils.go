package getsnpevidencesubtasks

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"strings"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
)

// GenerateRandomBytes generates a random 64-byte array using crypto/rand.
//
// Returns:
//   - [64]byte: A 64-byte array filled with cryptographically secure random bytes.
//
// Panics:
//   - If there is an error while generating random bytes.
func GenerateRandomBytes() [64]byte {
	var b [64]byte
	_, err := rand.Read(b[:])
	if err != nil {
		panic("error while generating random bytes")
	}
	return b
}

// ExtractModelFromVcekCertIssuer extracts the AMD SEV SNP model from the issuer's CN field in the provided VCEK certificate.
// The issuer's CN field is expected to be in the format "SEV-<model>".
//
// Parameters:
//   - vcekCert: A pointer to an x509.Certificate containing the VCEK certificate. Must be non-nil
//
// Returns:
//   - domain.AMDSEVSNPModel: The extracted AMD SEV SNP model.
//   - error: An error if the issuer CN format is invalid or the model is unknown.
func ExtractModelFromVcekCertIssuer(vcekCert *x509.Certificate) (domain.AMDSEVSNPModel, error) {
	issuer := vcekCert.Issuer.CommonName
	if !strings.HasPrefix(issuer, "SEV-") {
		return domain.ENUM_AMD_SEV_SNP_MODEL_UNKNOWN, fmt.Errorf("invalid issuer CN format")
	}
	modelStr := strings.TrimPrefix(issuer, "SEV-")
	switch modelStr {
	case "Milan":
		return domain.ENUM_AMD_SEV_SNP_MODEL_MILAN, nil
	case "Genoa":
		return domain.ENUM_AMD_SEV_SNP_MODEL_GENOA, nil
	case "Bergamo":
		return domain.ENUM_AMD_SEV_SNP_MODEL_BERGAMO, nil
	case "Siena":
		return domain.ENUM_AMD_SEV_SNP_MODEL_SIENA, nil
	case "Turin":
		return domain.ENUM_AMD_SEV_SNP_MODEL_TURIN, nil
	default:
		return domain.ENUM_AMD_SEV_SNP_MODEL_UNKNOWN, fmt.Errorf("unknown AMD SEV SNP model: %s", modelStr)
	}
}
