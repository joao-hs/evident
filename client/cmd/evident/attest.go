package evident

import (
	"github.com/spf13/cobra"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/sanitize"
)

var attestCmd = &cobra.Command{
	Use:   "attest <target-ip> <snp|tdx> <avm|ec2|gce>",
	Short: "Attest a remote confidential VM that is running an Evident server",

	Args: cobra.ExactArgs(3),

	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		setupLogger(cmd)
		debugPrintFlags(cmd)
	},

	RunE: func(cmd *cobra.Command, args []string) error {
		var err error

		targetIP, err := sanitize.TargetIP(args[0])
		if err != nil {
			return err
		}
		securePlatform, err := sanitize.SecurePlatform(args[1])
		if err != nil {
			return err
		}
		cloudProvider, err := sanitize.CloudServiceProvider(args[2])
		if err != nil {
			return err
		}
		targetPort, err := sanitize.TargetPort(cmd.Flag("target-port").Value.String())
		if err != nil {
			return err
		}
		cpuCount, err := sanitize.CPUCount(cmd.Flag("cpu-count").Value.String())
		if err != nil {
			return err
		}
		var optCpuCount *uint8 = nil
		if cpuCount != 0 {
			optCpuCount = &cpuCount
		}
		expectedPcrPath := cmd.Flag("expected-pcrs").Value.String()
		var optExpectedPCRs *domain.ExpectedPcrDigests = nil
		if expectedPcrPath != "" {
			expectedPCRs, err := sanitize.ExpectedPcrDigests(expectedPcrPath)
			if err != nil {
				return err
			}
			optExpectedPCRs = &expectedPCRs
		}

		cmd.SilenceUsage = true

		verifier, err := attest.NewVerifier(securePlatform, cloudProvider)
		if err != nil {
			return err
		}

		return verifier.Attest(targetIP, targetPort, optCpuCount, optExpectedPCRs, nil)
	},
}

func init() {
	attestCmd.Flags().Uint8("cpu-count", 0, "Number of vCPUs of the target confidential VM. If not provided, the client will attempt to reproduce the measurement for common CPU counts (e.g. 1, 2, 4, 8, ...).")
	attestCmd.Flags().Uint16P("target-port", "p", 5000, "Port on which the target Evident server is listening")
	attestCmd.Flags().String("expected-pcrs", "", "Path to the JSON file containing the expected PCR digests generated with evident measure")
	attestCmd.Flags().Bool("use-trusted-packages", false, "Use packages at /etc/evident/trusted-packages/")
	attestCmd.MarkFlagsOneRequired("expected-pcrs", "use-trusted-packages")
	attestCmd.MarkFlagsMutuallyExclusive("expected-pcrs", "use-trusted-packages")
	rootCmd.AddCommand(attestCmd)
}
