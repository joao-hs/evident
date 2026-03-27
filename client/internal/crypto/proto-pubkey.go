package crypto

import (
	"bytes"

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
