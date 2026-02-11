package evident

import (
	"github.com/spf13/cobra"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/sanitize"
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

		targetIP, err := sanitize.TargetIP(args[0])
		if err != nil {
			return err
		}
		targetPort, err := sanitize.TargetPort(args[1])
		if err != nil {
			return err
		}
		cpuCount, err := sanitize.CpuCount(args[2])
		if err != nil {
			return err
		}
		securePlatform, err := sanitize.SecurePlatform(args[3])
		if err != nil {
			return err
		}
		cloudProvider, err := sanitize.CloudServiceProvider(args[4])
		if err != nil {
			return err
		}
		expectedPCRs, err := sanitize.ExpectedPcrDigests(args[5])
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

func init() {
	rootCmd.AddCommand(attestCmd)
}
