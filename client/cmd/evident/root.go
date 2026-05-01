package evident

import (
	"os"

	"github.com/spf13/cobra"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/dotevident"
)

var rootCmd = &cobra.Command{
	Use:   "evident",
	Short: "evident is a CLI application to manage confidential virtual machines",
	Long: `Evident helps manage confidential virtual machines, including building, measuring,
attesting, packaging, and serving attestation-related workflows.

Use "evident <command> --help" for details on a specific subcommand.`,
	Example: `  evident --help
  evident attest --help`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		dotevident.Get()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().Bool("debug", false, "enable debug output")
}
