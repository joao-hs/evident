package evident

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
)

var attestCmd = &cobra.Command{
	Use:   "attest <target-ip> <target-port> <cpu-count> <snp|tdx> <avm|ec2|gce> <expected-pcrs-json-path>",
	Short: "Attest a remote CVM that is running an Evident server",

	Args: cobra.ExactArgs(6),

	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		debugPrintFlags(cmd)
		setupLogger(cmd)
	},

	RunE: func(cmd *cobra.Command, args []string) error {
		var err error

		// TODO: validate arguments
		targetIP := args[0]
		targetPort := args[1]
		cpuCount, err := validateCPUCount(args[2])
		if err != nil {
			return err
		}
		securePlatform := args[3]
		cloudProvider := args[4]
		expectedPCRs, err := validateExpectedPCRs(args[5])
		if err != nil {
			return err
		}
		cmd.SilenceUsage = true

		attestor, err := attest.NewAttestor()
		if err != nil {
			return err
		}

		return attestor.Attest(targetIP, targetPort, cpuCount, securePlatform, cloudProvider, expectedPCRs)
	},
}

func validateCPUCount(cpuCountStr string) (uint32, error) {
	cpuCount, err := strconv.ParseUint(cpuCountStr, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid CPU count: %v", err)
	}
	if cpuCount == 0 {
		return 0, fmt.Errorf("CPU count must be greater than 0")
	}
	return uint32(cpuCount), nil
}

func validateExpectedPCRs(expectedPCRsPath string) (domain.ExpectedPcrDigests, error) {
	info, err := os.Stat(expectedPCRsPath)
	if err != nil {
		return domain.ExpectedPcrDigests{}, fmt.Errorf("failed to access expected PCRs file: %v", err)
	}

	if info.IsDir() {
		return domain.ExpectedPcrDigests{}, fmt.Errorf("expected PCRs path is a directory, not a file")
	}

	file, err := os.Open(expectedPCRsPath)
	if err != nil {
		return domain.ExpectedPcrDigests{}, fmt.Errorf("failed to open expected PCRs file: %v", err)
	}
	defer file.Close()

	rawBytes, err := os.ReadFile(expectedPCRsPath)
	if err != nil {
		return domain.ExpectedPcrDigests{}, fmt.Errorf("failed to read expected PCRs file: %v", err)
	}

	expectedPCRs := domain.ExpectedPcrDigests{}
	if err := json.Unmarshal(rawBytes, &expectedPCRs); err != nil {
		return domain.ExpectedPcrDigests{}, fmt.Errorf("failed to parse expected PCRs JSON: %v", err)
	}

	return expectedPCRs, nil
}


func init() {
	rootCmd.AddCommand(attestCmd)
}
