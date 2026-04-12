package dotevident

import "encoding/json"

type cloudprovider int

const (
	_CLOUDPROVIDER_UNKNOWN cloudprovider = iota
	_CLOUDPROVIDER_AVM
	_CLOUDPROVIDER_EC2
	_CLOUDPROVIDER_GCE
)

func (c cloudprovider) String() string {
	return [...]string{
		"unknown_csp",
		"avm",
		"ec2",
		"gce",
	}[c]
}

func (c *cloudprovider) FromString(str string) cloudprovider {
	return map[string]cloudprovider{
		"unknown_csp": _CLOUDPROVIDER_UNKNOWN,
		"avm":         _CLOUDPROVIDER_AVM,
		"ec2":         _CLOUDPROVIDER_EC2,
		"gce":         _CLOUDPROVIDER_GCE,
	}[str]
}

func (c cloudprovider) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

func (c *cloudprovider) UnmarshalJSON(data []byte) error {
	var val string
	err := json.Unmarshal(data, &val)
	if err != nil {
		return err
	}
	*c = c.FromString(val)
	return nil
}
