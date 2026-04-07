package dotevident

import "encoding/json"

type cloudprovider int

const (
	_CLOUDPROVIDER_UNKNOWN cloudprovider = iota
	_CLOUDPROVIDER_AVM
	_CLOUDPROVIDER_EC2
	_CLOUDPROVIDER_GCE
)

func (self cloudprovider) String() string {
	return [...]string{
		"unknown_csp",
		"avm",
		"ec2",
		"gce",
	}[self]
}

func (self *cloudprovider) FromString(str string) cloudprovider {
	return map[string]cloudprovider{
		"unknown_csp": _CLOUDPROVIDER_UNKNOWN,
		"avm":         _CLOUDPROVIDER_AVM,
		"ec2":         _CLOUDPROVIDER_EC2,
		"gce":         _CLOUDPROVIDER_GCE,
	}[str]
}

func (self cloudprovider) MarshalJSON() ([]byte, error) {
	return json.Marshal(self.String())
}

func (self *cloudprovider) UnmarshalJSON(data []byte) error {
	var status string
	err := json.Unmarshal(data, &status)
	if err != nil {
		return err
	}
	*self = self.FromString(status)
	return nil
}
