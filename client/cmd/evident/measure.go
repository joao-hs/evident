package evident

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/domain"
	"gitlab.com/dpss-inesc-id/achilles-cvm/client/internal/measure"
)

var measureCmd = &cobra.Command{
	Use:   "measure <path-to-image> [<output-file>]",
	Short: "Measure expected TPM values for PCRs 4, 11 and 12",

	Args: cobra.RangeArgs(1, 2),

	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		debugPrintFlags(cmd)
		setupLogger(cmd)
	},

	RunE: func(cmd *cobra.Command, args []string) error {
		var err error

		imagePath, err := validateImagePath(args[0])
		if err != nil {
			return err
		}
		outputFile := ""
		if len(args) == 2 {
			outputFile, err = validateOutputFilePath(args[1])
			if err != nil {
				return err
			}
		}
		cmd.SilenceUsage = true

		vmImageMeasurer, err := measure.NewVMImageMeasurer()
		if err != nil {
			return err
		}

		show, err := cmd.Flags().GetBool("show")
		if err != nil {
			panic("could not parse 'show' flag")
		}
		if show {
			vmImageMeasurer.ShowMeasureImageCommands(imagePath, outputFile)
			return nil
		}

		measures, err := vmImageMeasurer.MeasureImage(imagePath)
		if err != nil {
			return err
		}

		var outputMeasureJsonStruct domain.ExpectedPcrDigests

		for i := range 24 {
			if digest, ok := measures[i]; ok {
				if ok := outputMeasureJsonStruct.SetDigestAtIndex(i, digest); !ok {
					return fmt.Errorf("could not set digest for PCR index %d", i)
				}
			}
		}

		outputMeasureString, err := json.MarshalIndent(outputMeasureJsonStruct, "", "  ")
		if err != nil {
			return err
		}

		if outputFile != "" {
			err = os.WriteFile(outputFile, outputMeasureString, 0644)
			if err != nil {
				return fmt.Errorf("could not write output to file: %s", err.Error())
			}
		} else {
			fmt.Println(string(outputMeasureString))
		}

		return nil
	},
}

func validateImagePath(imagePath string) (string, error) {
	return validateToAbsFilepath(imagePath, "image path")
}

func validateOutputFilePath(outputFilePath string) (string, error) {
	return validateToAbsFilepath(outputFilePath, "output file path")
}

func init() {
	measureCmd.Flags().Bool("show", false, "show equivalent commands instead of executing them")
	rootCmd.AddCommand(measureCmd)
}
