package cmd

import (
	"errors"
	"github.com/spf13/cobra"
	"imprimatur/display"
)

var displayCmd = &cobra.Command{
	Use:   "display",
	Short: "Display the signed file",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return errors.New("no path to a file to display was provided")
		}

		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		display.Display(args[0])
	},
}

func init() {
	rootCmd.AddCommand(displayCmd)
}
