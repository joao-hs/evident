package sanitize

import (
	"encoding/json"
	"fmt"
	"os"

	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
)

func ExpectedPcrDigests(expectedPcrDigestPath string) (domain.ExpectedPcrDigests, error) {
	if expectedPcrDigestPath == "" {
		return domain.ExpectedPcrDigests{}, nil
	}

	if !fileExists(expectedPcrDigestPath) {
		return domain.ExpectedPcrDigests{}, fmt.Errorf("file does not exist: %s", expectedPcrDigestPath)
	}

	bytes, err := os.ReadFile(expectedPcrDigestPath)
	if err != nil {
		return domain.ExpectedPcrDigests{}, fmt.Errorf("failed to read expected PCRs file: %v", err)
	}

	expectedPcrs := domain.ExpectedPcrDigests{}
	err = json.Unmarshal(bytes, &expectedPcrs)
	if err != nil {
		return domain.ExpectedPcrDigests{}, fmt.Errorf("failed to parse expected PCRs JSON: %v", err)
	}

	return expectedPcrs, nil
}
