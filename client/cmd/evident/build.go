package evident

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/build"
)

var buildCmd = &cobra.Command{
	Use:   "build <path-to>/flake.nix <variation> <output-path>",
	Short: "Build VM image from Nix flake",

	Args: cobra.ExactArgs(3),

	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		debugPrintFlags(cmd)
		setupLogger(cmd)
	},

	RunE: func(cmd *cobra.Command, args []string) error {
		var err error

		nixFlakePath, err := validateNixFlakePath(args[0])
		if err != nil {
			return err
		}
		variation := args[1]
		if err := validateVMImageVariation(variation); err != nil {
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
			vmImageBuilder.ShowBuildImageCommands(nixFlakePath, variation, imageOutputPath)
			return nil
		}

		err = vmImageBuilder.BuildImage(nixFlakePath, variation, imageOutputPath)
		if err != nil {
			return err
		}

		fmt.Printf("The VM image built from %s (variation: %s) is available at %s\n", nixFlakePath, variation, imageOutputPath)
		return nil
	},
}

func validateNixFlakePath(nixFlakePath string) (string, error) {
	absPath, err := filepath.Abs(nixFlakePath)
	if err != nil {
		return "", err
	}

	info, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("path does not exist")
		}
		return "", err
	}

	if info.IsDir() {
		return "", fmt.Errorf("path is a directory, not a file")
	}

	if filepath.Base(absPath) != "flake.nix" {
		return "", fmt.Errorf("file must be named 'flake.nix'")
	}

	dir := filepath.Dir(absPath)

	return dir, nil
}

func validateVMImageVariation(variation string) error {
	// TODO: nix search (? maybe)
	return nil
}

func init() {
	buildCmd.Flags().Bool("show", false, "show equivalent commands instead of executing them")
	rootCmd.AddCommand(buildCmd)
}
