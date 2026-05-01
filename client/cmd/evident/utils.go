package evident

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/dotevident"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/global/log"
)

func debugPrintFlags(cmd *cobra.Command) {
	val, err := cmd.Flags().GetBool("debug")
	if err != nil {
		panic("could not access debug flag")
	}
	if val {
		cmd.Flags().Visit(func(f *pflag.Flag) {
			if f.Changed {
				log.Get().Debugf("flag \"%s\" = %s", f.Name, f.Value.String())
			}
		})
	}
}

func setupLogger(cmd *cobra.Command) error {
	dot := dotevident.Get()
	logFilePath := dot.GetLogFilePath(cmd.Name())
	err := log.GetLogFileSyncer().Swap(logFilePath)
	if err != nil {
		return err
	}
	val, err := cmd.Flags().GetBool("debug")
	if err != nil {
		return fmt.Errorf("could not access debug flag: %v", err)
	}
	if val {
		log.Get().SetDebugLevel()
	}
	return nil
}

func preRunWithLogger(cmd *cobra.Command, args []string) error {
	if err := setupLogger(cmd); err != nil {
		return err
	}
	debugPrintFlags(cmd)
	return nil
}

func validateToAbsFilepath(filePath string, pathName string) (string, error) {
	if filePath == "" {
		return "", fmt.Errorf("path for %s is empty", pathName)
	}
	absFilePath, err := filepath.Abs(filePath)
	if err != nil {
		return "", fmt.Errorf("could not get absolute path for %s: %v", pathName, err)
	}
	return absFilePath, nil
}
