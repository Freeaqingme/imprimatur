package cmd

import (
	"errors"
	"imprimatur/verifier"

	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify the signatures attached to a file",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return errors.New("no path to a file to verify was provided")
		}

		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		verifier.Verify(args[0])
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)
}
