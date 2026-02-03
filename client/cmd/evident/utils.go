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
				log.Get().Debugf("flag \"%s\" = %s\n", f.Name, f.Value.String())
			}
		})
	}
}

func setupLogger(cmd *cobra.Command) error {
	dot := dotevident.Get()
	logFilePath := dot.GetLogFilePath(cmd.Name())
	log.GetLogFileSyncer().Swap(logFilePath)
	val, err := cmd.Flags().GetBool("debug")
	if val {
		log.Get().SetDebugLevel()
	}
	return err
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
