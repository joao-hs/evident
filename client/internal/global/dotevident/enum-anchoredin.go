package dotevident

import "encoding/json"

type anchoredIn int

const (
	_ANCHOREDIN_UNKNOWN anchoredIn = iota
	_ANCHOREDIN_AVM
	_ANCHOREDIN_EC2
	_ANCHOREDIN_GCE
	_ANCHOREDIN_AMD
	_ANCHOREDIN_INTEL
)

func (self anchoredIn) String() string {
	return [...]string{
		"unknown anchoring",
		"anchored in avm",
		"anchored in ec2",
		"anchored in gce",
		"anchored in amd",
		"anchored in intel",
	}[self]
}

func (self *anchoredIn) FromString(str string) anchoredIn {
	return map[string]anchoredIn{
		"unknown anchoring": _ANCHOREDIN_UNKNOWN,
		"anchored in avm":   _ANCHOREDIN_AVM,
		"anchored in ec2":   _ANCHOREDIN_EC2,
		"anchored in gce":   _ANCHOREDIN_GCE,
		"anchored in amd":   _ANCHOREDIN_AMD,
		"anchored in intel": _ANCHOREDIN_INTEL,
	}[str]
}

func (self anchoredIn) MarshalJSON() ([]byte, error) {
	return json.Marshal(self.String())
}

func (self *anchoredIn) UnmarshalJSON(data []byte) error {
	var status string
	err := json.Unmarshal(data, &status)
	if err != nil {
		return err
	}
	*self = self.FromString(status)
	return nil
}
