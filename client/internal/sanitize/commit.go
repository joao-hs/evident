package sanitize

import (
	"fmt"
	"regexp"
)

var commitHashRegex = regexp.MustCompile(`^[a-f0-9]+$`)

func CommitHash(commitHashStr string) (string, error) {
	if !commitHashRegex.MatchString(commitHashStr) {
		return "", fmt.Errorf("invalid commit hash: %s", commitHashStr)
	}

	return commitHashStr, nil
}
