package evident

import (
	"github.com/spf13/cobra"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/sanitize"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/submitpackage"
)

var submitPackageCmd = &cobra.Command{
	Use:   "submit-package <package-dir> <target>",
	Short: "Submit a package as trusted for a certificate issuer",

	Args: cobra.ExactArgs(2),

	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		setupLogger(cmd)
		debugPrintFlags(cmd)
	},

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
