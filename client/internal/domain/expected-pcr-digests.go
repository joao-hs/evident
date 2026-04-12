package domain

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
)

type ExpectedPcrDigests struct {
	Records []struct {
		Pcr     int `json:"pcr"`
		Digests []struct {
			HashAlg string `json:"hashAlg"`
			Digest  string `json:"digest"`
		} `json:"digests"`
	} `json:"records"`

	len            int
	finalDigests   map[int][]byte
	expectedDigest map[HashAlgorithm]string
}

func (e *ExpectedPcrDigests) ComputeExpectedDigest(hashAlg HashAlgorithm) (string, error) {
	var (
		hash     func([]byte) []byte
		hashSize int
	)

	switch hashAlg {
	case ENUM_HASH_ALGORITHM_SHA1:
		hash = func(b []byte) []byte {
			tmp := sha1.Sum(b)
			return tmp[:]
		}
		hashSize = 20
	case ENUM_HASH_ALGORITHM_SHA256:
		hash = func(b []byte) []byte {
			tmp := sha256.Sum256(b)
			return tmp[:]
		}
		hashSize = 32
	case ENUM_HASH_ALGORITHM_SHA384:
		hash = func(b []byte) []byte {
			tmp := sha512.Sum384(b)
			return tmp[:]
		}
		hashSize = 48
	case ENUM_HASH_ALGORITHM_SHA512:
		hash = func(b []byte) []byte {
			tmp := sha512.Sum512(b)
			return tmp[:]
		}
		hashSize = 64
	default:
		return "", fmt.Errorf("unknown hashing algorithm")
	}

	if len(e.Records) == 0 {
		return "", fmt.Errorf("there are no expected measurement records")
	}

	if e.expectedDigest == nil {
		e.expectedDigest = make(map[HashAlgorithm]string)
	}

	if e.expectedDigest[hashAlg] != "" {
		return e.expectedDigest[hashAlg], nil
	}

	newInitialPcrValue := func() []byte {
		return make([]byte, hashSize)
	}

	extend := func(base []byte, extension []byte) []byte {
		if len(base) != hashSize {
			panic("expected base to be the same length as the resulting hash size")
		}

		if len(base) != len(extension) {
			panic("expected extension to be the same lenght as the base")
		}

		concat := make([]byte, hashSize*2)
		copy(concat[:hashSize], base)
		copy(concat[hashSize:], extension)

		return hash(concat)
	}

	e.finalDigests = make(map[int][]byte)
	for i, record := range e.Records {
		if _, ok := e.finalDigests[record.Pcr]; !ok {
			e.finalDigests[record.Pcr] = newInitialPcrValue()
		}
		for _, hashDigest := range record.Digests {
			if hashDigest.HashAlg != hashAlg.String() {
				continue
			}
			extension, err := hex.DecodeString(hashDigest.Digest)
			if err != nil || len(extension) != len(e.finalDigests[record.Pcr]) {
				return "", fmt.Errorf("error while decoding digest from record number %d", i)
			}
			e.finalDigests[record.Pcr] = extend(e.finalDigests[record.Pcr], extension)
		}
	}

	e.finalDigests[12] = newInitialPcrValue() // PCR12 must be asserted to zero since it measures overwrites

	concat := make([]byte, len(e.finalDigests)*hashSize)
	offset := 0
	for pcrIndex := range 23 { // at most 24 PCR indices
		if finalDigest, ok := e.finalDigests[pcrIndex]; ok {
			offset += copy(concat[offset:], finalDigest)
		}
	}

	expectedDigest := hash(concat)

	expectedDigestStr := hex.EncodeToString(expectedDigest)
	e.expectedDigest[hashAlg] = expectedDigestStr

	return expectedDigestStr, nil
}
