package domain

import (
	"encoding/json"
	"strings"
)

type EvidenceType int

const (
	ENUM_EVIDENCE_TYPE_UNKNOWN EvidenceType = iota
	ENUM_EVIDENCE_TYPE_HARDWARE
	ENUM_EVIDENCE_TYPE_SOFTWARE
)

const (
	_EVIDENCE_TYPE_UNKNOWN_STR  = "Unknown evidence type"
	_EVIDENCE_TYPE_HARDWARE_STR = "Hardware evidence"
	_EVIDENCE_TYPE_SOFTWARE_STR = "Software evidence"
)

func (e EvidenceType) String() string {
	return [...]string{
		_EVIDENCE_TYPE_UNKNOWN_STR,
		_EVIDENCE_TYPE_HARDWARE_STR,
		_EVIDENCE_TYPE_SOFTWARE_STR,
	}[e]
}

func (e *EvidenceType) FromString(str string) EvidenceType {
	return map[string]EvidenceType{
		strings.ToLower(_EVIDENCE_TYPE_UNKNOWN_STR):  ENUM_EVIDENCE_TYPE_UNKNOWN,
		strings.ToLower(_EVIDENCE_TYPE_HARDWARE_STR): ENUM_EVIDENCE_TYPE_HARDWARE,
		strings.ToLower(_EVIDENCE_TYPE_SOFTWARE_STR): ENUM_EVIDENCE_TYPE_SOFTWARE,
	}[strings.ToLower(str)]
}

func (e EvidenceType) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.String())
}

func (e *EvidenceType) UnmarshalJSON(data []byte) error {
	var temp string
	err := json.Unmarshal(data, &temp)
	if err != nil {
		return err
	}
	*e = e.FromString(temp)
	return nil
}
