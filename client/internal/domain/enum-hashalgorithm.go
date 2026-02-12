package domain

import "encoding/json"

type HashAlgorithm int

const (
	ENUM_HASH_ALGORITHM_UNKNOWN HashAlgorithm = iota
	ENUM_HASH_ALGORITHM_SHA1
	ENUM_HASH_ALGORITHM_SHA256
	ENUM_HASH_ALGORITHM_SHA384
	ENUM_HASH_ALGORITHM_SHA512
)

const (
	_ENUM_HASH_ALGORITHM_UNKNOWN_STR = "Unknown hashing algorithm"
	_ENUM_HASH_ALGORITHM_SHA1_STR    = "sha1"
	_ENUM_HASH_ALGORITHM_SHA256_STR  = "sha256"
	_ENUM_HASH_ALGORITHM_SHA384_STR  = "sha384"
	_ENUM_HASH_ALGORITHM_SHA512_STR  = "sha512"
)

func (self HashAlgorithm) String() string {
	return [...]string{
		_ENUM_HASH_ALGORITHM_UNKNOWN_STR,
		_ENUM_HASH_ALGORITHM_SHA1_STR,
		_ENUM_HASH_ALGORITHM_SHA256_STR,
		_ENUM_HASH_ALGORITHM_SHA384_STR,
		_ENUM_HASH_ALGORITHM_SHA512_STR,
	}[self]
}

func (self *HashAlgorithm) FromString(status string) HashAlgorithm {
	return map[string]HashAlgorithm{
		_ENUM_HASH_ALGORITHM_UNKNOWN_STR: ENUM_HASH_ALGORITHM_UNKNOWN,
		_ENUM_HASH_ALGORITHM_SHA1_STR:    ENUM_HASH_ALGORITHM_SHA1,
		_ENUM_HASH_ALGORITHM_SHA256_STR:  ENUM_HASH_ALGORITHM_SHA256,
		_ENUM_HASH_ALGORITHM_SHA384_STR:  ENUM_HASH_ALGORITHM_SHA384,
		_ENUM_HASH_ALGORITHM_SHA512_STR:  ENUM_HASH_ALGORITHM_SHA512,
	}[status]
}

func (self HashAlgorithm) MarshalJSON() ([]byte, error) {
	return json.Marshal(self.String())
}

func (self *HashAlgorithm) UnmarshalJSON(data []byte) error {
	var temp string
	err := json.Unmarshal(data, &temp)
	if err != nil {
		return err
	}
	*self = self.FromString(temp)
	return nil
}
