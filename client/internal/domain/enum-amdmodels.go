package domain

import (
	"encoding/json"
	"strings"
)

type AMDSEVSNPModel int

const (
	ENUM_AMD_SEV_SNP_MODEL_UNKNOWN AMDSEVSNPModel = iota
	ENUM_AMD_SEV_SNP_MODEL_MILAN
	ENUM_AMD_SEV_SNP_MODEL_GENOA
	ENUM_AMD_SEV_SNP_MODEL_BERGAMO
	ENUM_AMD_SEV_SNP_MODEL_SIENA
	ENUM_AMD_SEV_SNP_MODEL_TURIN
)

const (
	_AMD_SEV_SNP_MODEL_UNKNOWN_STR = "Unknown AMD model"
	_AMD_SEV_SNP_MODEL_MILAN_STR   = "Milan"
	_AMD_SEV_SNP_MODEL_GENOA_STR   = "Genoa"
	_AMD_SEV_SNP_MODEL_BERGAMO_STR = "Bergamo"
	_AMD_SEV_SNP_MODEL_SIENA_STR   = "Siena"
	_AMD_SEV_SNP_MODEL_TURIN_STR   = "Turin"
)

func (self AMDSEVSNPModel) String() string {
	return [...]string{
		_AMD_SEV_SNP_MODEL_UNKNOWN_STR,
		_AMD_SEV_SNP_MODEL_MILAN_STR,
		_AMD_SEV_SNP_MODEL_GENOA_STR,
		_AMD_SEV_SNP_MODEL_BERGAMO_STR,
		_AMD_SEV_SNP_MODEL_SIENA_STR,
		_AMD_SEV_SNP_MODEL_TURIN_STR,
	}[self]
}

func (self *AMDSEVSNPModel) FromString(str string) AMDSEVSNPModel {
	return map[string]AMDSEVSNPModel{
		strings.ToLower(_AMD_SEV_SNP_MODEL_UNKNOWN_STR): ENUM_AMD_SEV_SNP_MODEL_UNKNOWN,
		strings.ToLower(_AMD_SEV_SNP_MODEL_MILAN_STR):   ENUM_AMD_SEV_SNP_MODEL_MILAN,
		strings.ToLower(_AMD_SEV_SNP_MODEL_GENOA_STR):   ENUM_AMD_SEV_SNP_MODEL_GENOA,
		strings.ToLower(_AMD_SEV_SNP_MODEL_BERGAMO_STR): ENUM_AMD_SEV_SNP_MODEL_BERGAMO,
		strings.ToLower(_AMD_SEV_SNP_MODEL_SIENA_STR):   ENUM_AMD_SEV_SNP_MODEL_SIENA,
		strings.ToLower(_AMD_SEV_SNP_MODEL_TURIN_STR):   ENUM_AMD_SEV_SNP_MODEL_TURIN,
	}[strings.ToLower(str)]
}

func (self AMDSEVSNPModel) MarshalJSON() ([]byte, error) {
	return json.Marshal(self.String())
}

func (self *AMDSEVSNPModel) UnmarshalJSON(data []byte) error {
	var status string
	err := json.Unmarshal(data, &status)
	if err != nil {
		return err
	}
	*self = self.FromString(status)
	return nil
}
