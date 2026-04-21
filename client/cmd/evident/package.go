package evident

import (
	"path/filepath"

	"github.com/spf13/cobra"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/build"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/measure"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/packager"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/sanitize"
)

var packageCmd = &cobra.Command{
	Use:   "package",
	Short: "Build VM image from Nix flake, measure it, and vouch the package's manifest file",

	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		setupLogger(cmd)
		debugPrintFlags(cmd)
	},

	RunE: func(cmd *cobra.Command, args []string) error {
		var err error

		nixFlakeDirPath, err := sanitize.NixFlakeDirFromPath(cmd.Flag("flake").Value.String())
		if err != nil {
			return err
		}
		variation, err := sanitize.ImageVariation(cmd.Flag("variation").Value.String())
		if err != nil {
			return err
		}
		outputDirPath, err := filepath.Abs(cmd.Flag("output-dir").Value.String())
		if err != nil {
			return err
		}
		repoUrl, err := sanitize.RepoUrl(cmd.Flag("repo").Value.String())
		if err != nil {
			return err
		}
		commitHash, err := sanitize.CommitHash(cmd.Flag("commit").Value.String())
		if err != nil {
			return err
		}
		keyId, err := sanitize.KeyId(cmd.Flag("key").Value.String())
		if err != nil {
			return err
		}
		cmd.SilenceUsage = true

		vmImageBuilder, err := build.NewVMImageBuilder()
		if err != nil {
			return err
		}

		vmImageMeasurer, err := measure.NewVMImageMeasurer()
		if err != nil {
			return err
		}

		pkg, err := packager.NewPackager(vmImageBuilder, vmImageMeasurer, keyId)
		if err != nil {
			return err
		}

		show, err := cmd.Flags().GetBool("show")
		if err != nil {
			panic("could not parse 'show' flag")
		}
		if show {
			log.Get().Infoln(pkg.GetEquivalentCommands(nixFlakeDirPath, variation, outputDirPath))
			return nil
		}

		err = pkg.Package(nixFlakeDirPath, variation, outputDirPath, repoUrl, commitHash)
		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	packageCmd.Flags().String("flake", "./flake.nix", "path to the nix flake")
	packageCmd.Flags().String("variation", "", "package variation inside the nix flake")
	packageCmd.Flags().StringP("output-dir", "o", "/etc/evident/trusted-packages", "output directory path where to store the built package")
	packageCmd.Flags().String("repo", "", "git repository url to include in the manifest file")
	packageCmd.Flags().String("commit", "", "git commit hash to include in the manifest file")
	packageCmd.Flags().StringP("key", "k", "", "gpg key id to sign the manifest file (default gpg key if exists, otherwise aborts)")
	packageCmd.Flags().Bool("show", false, "show equivalent commands instead of executing them; default: false")
	packageCmd.MarkFlagRequired("variation")
	packageCmd.MarkFlagRequired("repo")
	packageCmd.MarkFlagRequired("commit")
	rootCmd.AddCommand(packageCmd)
}
