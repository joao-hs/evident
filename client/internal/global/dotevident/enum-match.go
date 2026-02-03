package dotevident

import "encoding/json"

type match int

const (
	_MATCH_UNKNOWN match = iota
	_MATCH_NOMATCH
	_MATCH_MATCH
)

func (self match) String() string {
	return [...]string{
		"unknown",
		"no-match",
		"match",
	}[self]
}

func (self *match) FromString(status string) match {
	return map[string]match{
		"unknown":  _MATCH_UNKNOWN,
		"no-match": _MATCH_NOMATCH,
		"match":    _MATCH_MATCH,
	}[status]
}

func (self match) MarshalJSON() ([]byte, error) {
	return json.Marshal(self.String())
}

func (self *match) UnmarshalJSON(data []byte) error {
	var status string
	err := json.Unmarshal(data, &status)
	if err != nil {
		return err
	}
	*self = self.FromString(status)
	return nil
}
