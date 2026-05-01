package evident

import (
	"github.com/spf13/cobra"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/sanitize"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/submitpackage"
)

var submitPackageCmd = &cobra.Command{
	Use:     "submit-package <package-dir> <host:port>",
	Short:   "Submit a package as trusted for a certificate issuer",
	Long:    "Submits a package directory to a certificate issuer target (host:port).",
	Example: `  evident submit-package ./package-dir 10.0.0.5:5010`,
	Args:    cobra.ExactArgs(2),
	PreRunE: preRunWithLogger,

	RunE: func(cmd *cobra.Command, args []string) error {
		var err error

		packageDir, err := validatePackagePath(args[0])
		if err != nil {
			return err
		}

		target, err := sanitize.Target(args[1])
		if err != nil {
			return err
		}

		packageSubmitter, err := submitpackage.NewPackageSubmitter(target)
		if err != nil {
			return err
		}
		cmd.SilenceUsage = true

		return packageSubmitter.SubmitPackage(packageDir)
	},
}

func validatePackagePath(path string) (string, error) {
	return validateToAbsFilepath(path, "package directory path")
}

func init() {
	rootCmd.AddCommand(submitPackageCmd)
}
