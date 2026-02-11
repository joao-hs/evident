package sanitize

import (
	"fmt"
	"strconv"
)

func CpuCount(cpuCountStr string) (uint8, error) {
	cpuCount, err := strconv.ParseUint(cpuCountStr, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("invalid cpu count: %v", err)
	}

	return sanitizeCpuCountInt(uint8(cpuCount))
}

func sanitizeCpuCountInt(cpuCount uint8) (uint8, error) {
	if cpuCount == 0 {
		return 0, fmt.Errorf("cpu count must be greater than 0")
	}

	return cpuCount, nil
}
