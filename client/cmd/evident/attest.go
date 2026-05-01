package evident

import (
	"bytes"
	"os"

	"github.com/spf13/cobra"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/attest"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/report"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/sanitize"
)

var attestCmd = &cobra.Command{
	Use:   "attest <target-ip> snp <ec2|gce>",
	Short: "Attest a remote confidential VM that is running an Evident server",
	Long: `Attest a remote confidential VM that is running an Evident server.

One of --expected-pcrs or --use-trusted-packages is required. For EC2 targets, provide --instance-id, if you are the confidential VM owner.`,
	Example: `  evident attest 10.0.0.5 snp ec2 --expected-pcrs ./pcrs.json --out-report ./attestation.html
  evident attest 10.0.0.5 snp gce --use-trusted-packages`,
	Args:    cobra.ExactArgs(3),
	PreRunE: preRunWithLogger,

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
		optCPUCount, err := sanitize.OptCPUCount(cmd.Flag("cpu-count").Value.String())
		if err != nil {
			return err
		}
		optInstanceId, err := sanitize.OptInstanceId(cmd.Flag("instance-id").Value.String())
		if err != nil {
			return err
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

		reportInput, err := verifier.Attest(targetIP, targetPort, optCPUCount, optInstanceId, optExpectedPCRs, nil)
		if err == nil {
			log.Get().Infoln("Attestation successful!")
		} else {
			log.Get().Errorln("Attestation failed:", err)
		}

		reportInput.ComputeVerdict()

		reportOutputPath := cmd.Flag("out-report").Value.String()
		if reportOutputPath == "" {
			return err
		}

		tmpl, templErr := report.GetTemplate()
		if templErr != nil {
			log.Get().Errorln("Failed to get report template:", templErr)
			if err == nil {
				return templErr
			}
			return err
		}
		var buf bytes.Buffer
		templErr = tmpl.Execute(&buf, reportInput)
		if templErr != nil {
			log.Get().Errorln("Failed to execute report template:", err)
			if err == nil {
				return templErr
			}
			return err
		}

		templErr = os.WriteFile(reportOutputPath, buf.Bytes(), 0644)
		if templErr != nil {
			log.Get().Errorln("Failed to write report to file:", templErr)
			log.Get().Debugf("Failed to write content: ```%s```", buf.String())
			if err == nil {
				return templErr
			}
		}

		log.Get().Infoln("Report generated at", reportOutputPath)

		return err
	},
}

func init() {
	attestCmd.Flags().Uint8("cpu-count", 0, "Number of vCPUs of the target confidential VM. If not provided, the client will attempt to reproduce the measurement for common CPU counts (e.g. 1, 2, 4, 8, ...).")
	attestCmd.Flags().StringP("instance-id", "i", "", "Instance ID of the target confidential VM (required for EC2 instances)")
	attestCmd.Flags().Uint16P("target-port", "p", 5000, "Port on which the target Evident server is listening")
	attestCmd.Flags().String("expected-pcrs", "", "Path to the JSON file containing the expected PCR digests generated with evident measure")
	attestCmd.Flags().Bool("use-trusted-packages", false, "Use packages at /etc/evident/trusted-packages/")
	attestCmd.Flags().String("out-report", "", "Path to save the generated HTML report (if not provided, the report won't be generated)")
	attestCmd.MarkFlagsOneRequired("expected-pcrs", "use-trusted-packages")
	attestCmd.MarkFlagsMutuallyExclusive("expected-pcrs", "use-trusted-packages")
	rootCmd.AddCommand(attestCmd)
}
