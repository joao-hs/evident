package domain

import (
	"reflect"
)

type ExpectedPcrDigests struct {
	Pcr0  string `json:"pcr0,omitempty"`
	Pcr1  string `json:"pcr1,omitempty"`
	Pcr2  string `json:"pcr2,omitempty"`
	Pcr3  string `json:"pcr3,omitempty"`
	Pcr4  string `json:"pcr4,omitempty"`
	Pcr5  string `json:"pcr5,omitempty"`
	Pcr6  string `json:"pcr6,omitempty"`
	Pcr7  string `json:"pcr7,omitempty"`
	Pcr8  string `json:"pcr8,omitempty"`
	Pcr9  string `json:"pcr9,omitempty"`
	Pcr10 string `json:"pcr10,omitempty"`
	Pcr11 string `json:"pcr11,omitempty"`
	Pcr12 string `json:"pcr12,omitempty"`
	Pcr13 string `json:"pcr13,omitempty"`
	Pcr14 string `json:"pcr14,omitempty"`
	Pcr15 string `json:"pcr15,omitempty"`
	Pcr16 string `json:"pcr16,omitempty"`
	Pcr17 string `json:"pcr17,omitempty"`
	Pcr18 string `json:"pcr18,omitempty"`
	Pcr19 string `json:"pcr19,omitempty"`
	Pcr20 string `json:"pcr20,omitempty"`
	Pcr21 string `json:"pcr21,omitempty"`
	Pcr22 string `json:"pcr22,omitempty"`
	Pcr23 string `json:"pcr23,omitempty"`
}

func (self *ExpectedPcrDigests) Len() int {
	count := 0
	val := reflect.ValueOf(self)
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		if field.Kind() == reflect.String && field.String() != "" {
			count++
		}
	}
	return count
}

func (self *ExpectedPcrDigests) GetDigestAtIndex(index int) (string, bool) {
	val := reflect.ValueOf(self).Elem()
	if index < 0 || index >= val.NumField() {
		return "", false
	}
	field := val.Field(index)
	if field.Kind() == reflect.String && field.String() != "" {
		return field.String(), true
	}
	return "", false
}

func (self *ExpectedPcrDigests) SetDigestAtIndex(index int, digest string) bool {
	val := reflect.ValueOf(self).Elem()
	if index < 0 || index >= val.NumField() {
		return false
	}
	field := val.Field(index)
	if field.Kind() == reflect.String {
		field.SetString(digest)
		return true
	}
	return false
}

func (self *ExpectedPcrDigests) AsSlice() []string {
	digests := make([]string, 0)
	for i := range 24 {
		digest, ok := self.GetDigestAtIndex(i)
		if ok {
			digests = append(digests, digest)
		} else {
			digests = append(digests, "")
		}
	}
	return digests
}
