package cmd

import (
	"errors"
	"imprimatur/imprimatur"

	"github.com/spf13/cobra"
)

var keyGrip string

// signCmd represents the sign command
var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a PDF file",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return errors.New("no path to pdf file provided")
		}

		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		imprimatur.Sign(keyGrip, args[0])
	},
}

func init() {
	rootCmd.AddCommand(signCmd)

	signCmd.Flags().StringVarP(&keyGrip, "keygrip", "", "", "The keygrip (see: gpg --list-keys --with-keygrip) of the key that should be used to sign")
	signCmd.MarkFlagRequired("keygrip")
}
