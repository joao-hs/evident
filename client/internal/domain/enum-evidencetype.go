package domain

import "encoding/json"

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

func (self EvidenceType) String() string {
	return [...]string{
		_EVIDENCE_TYPE_UNKNOWN_STR,
		_EVIDENCE_TYPE_HARDWARE_STR,
		_EVIDENCE_TYPE_SOFTWARE_STR,
	}[self]
}

func (self *EvidenceType) FromString(status string) EvidenceType {
	return map[string]EvidenceType{
		_EVIDENCE_TYPE_UNKNOWN_STR:  ENUM_EVIDENCE_TYPE_UNKNOWN,
		_EVIDENCE_TYPE_HARDWARE_STR: ENUM_EVIDENCE_TYPE_HARDWARE,
		_EVIDENCE_TYPE_SOFTWARE_STR: ENUM_EVIDENCE_TYPE_SOFTWARE,
	}[status]
}

func (self EvidenceType) MarshalJSON() ([]byte, error) {
	return json.Marshal(self.String())
}

func (self *EvidenceType) UnmarshalJSON(data []byte) error {
	var temp string
	err := json.Unmarshal(data, &temp)
	if err != nil {
		return err
	}
	*self = self.FromString(temp)
	return nil
}
