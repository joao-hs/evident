package dotevident

import "encoding/json"

type vmHealth int

const (
	_VMHEALTH_UNKNOWN vmHealth = iota
	_VMHEALTH_PENDING
	_VMHEALTH_ONLINE
	_VMHEALTH_OFFLINE
	_VMHEALTH_DELETED
)

func (self vmHealth) String() string {
	return [...]string{
		"unknown",
		"pending",
		"online",
		"offline",
		"deleted",
	}[self]
}

func (self *vmHealth) FromString(str string) vmHealth {
	return map[string]vmHealth{
		"unknown": _VMHEALTH_UNKNOWN,
		"pending": _VMHEALTH_PENDING,
		"online":  _VMHEALTH_ONLINE,
		"offline": _VMHEALTH_OFFLINE,
		"deleted": _VMHEALTH_DELETED,
	}[str]
}

func (self vmHealth) MarshalJSON() ([]byte, error) {
	return json.Marshal(self.String())
}

func (self *vmHealth) UnmarshalJSON(data []byte) error {
	var status string
	err := json.Unmarshal(data, &status)
	if err != nil {
		return err
	}
	*self = self.FromString(status)
	return nil
}
