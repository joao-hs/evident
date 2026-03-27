package evident

import (
	"path/filepath"

	"github.com/spf13/cobra"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/build"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/sanitize"
)

var buildCmd = &cobra.Command{
	Use:   "build <path-to>/flake.nix <package-variation> <output-path>",
	Short: "Build VM image from Nix flake",

	Args: cobra.ExactArgs(3),

	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		setupLogger(cmd)
		debugPrintFlags(cmd)
	},

	RunE: func(cmd *cobra.Command, args []string) error {
		var err error

		nixFlakeDirPath, err := sanitize.NixFlakeDirFromPath(args[0])
		if err != nil {
			return err
		}
		variation, err := sanitize.ImageVariation(args[1])
		if err != nil {
			return err
		}
		imageOutputPath, err := filepath.Abs(args[2])
		if err != nil {
			return err
		}
		cmd.SilenceUsage = true

		vmImageBuilder, err := build.NewVMImageBuilder()
		if err != nil {
			return err
		}

		show, err := cmd.Flags().GetBool("show")
		if err != nil {
			panic("could not parse 'show' flag")
		}
		if show {
			log.Get().Infoln(vmImageBuilder.GetEquivalentCommands(nixFlakeDirPath, variation, imageOutputPath))
			return nil
		}

		err = vmImageBuilder.BuildImage(nixFlakeDirPath, variation, imageOutputPath)
		if err != nil {
			return err
		}

		log.Get().Infof("The VM image built from %s (variation: %s) is available at %s\n", nixFlakeDirPath, variation, imageOutputPath)
		return nil
	},
}

func init() {
	buildCmd.Flags().Bool("show", false, "show equivalent commands instead of executing them")
	rootCmd.AddCommand(buildCmd)
}
