package sanitize

import (
	"fmt"
	"strconv"
)

func OptCPUCount(cpuCountStr string) (*uint8, error) {
	cpuCount, err := strconv.ParseUint(cpuCountStr, 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid cpu count: %v", err)
	}

	return sanitizeCpuCountInt(uint8(cpuCount))
}

func sanitizeCpuCountInt(cpuCount uint8) (*uint8, error) {
	if cpuCount == 0 {
		return nil, nil
	}

	return &cpuCount, nil
}
