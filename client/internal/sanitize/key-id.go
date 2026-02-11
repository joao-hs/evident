package sanitize

import (
	"errors"
	"regexp"
)

var gpgKeyIDPattern = regexp.MustCompile(`^[A-Fa-f0-9]{16}$`)

func KeyId(keyIdStr string) (string, error) {
	if keyIdStr == "" {
		return "", nil
	}

	if !gpgKeyIDPattern.MatchString(keyIdStr) {
		return "", errors.New("invalid GPG key ID format")
	}

	return keyIdStr, nil
}
