package evident

import (
	"os"

	"github.com/spf13/cobra"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/dotevident"
)

var rootCmd = &cobra.Command{
	Use:   "evident",
	Short: "evident is a CLI application to manage confidential virtual machines",
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
