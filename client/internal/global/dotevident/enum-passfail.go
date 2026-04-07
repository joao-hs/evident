package dotevident

import "encoding/json"

type passfail int

const (
	_PASSFAIL_UNKNOWN passfail = iota
	_PASSFAIL_FAIL
	_PASSFAIL_PASS
)

func (self passfail) String() string {
	return [...]string{
		"unknown",
		"fail",
		"pass",
	}[self]
}

func (self *passfail) FromString(str string) passfail {
	return map[string]passfail{
		"unknown": _PASSFAIL_UNKNOWN,
		"fail":    _PASSFAIL_FAIL,
		"pass":    _PASSFAIL_PASS,
	}[str]
}

func (self passfail) MarshalJSON() ([]byte, error) {
	return json.Marshal(self.String())
}

func (self *passfail) UnmarshalJSON(data []byte) error {
	var status string
	err := json.Unmarshal(data, &status)
	if err != nil {
		return err
	}
	*self = self.FromString(status)
	return nil
}
