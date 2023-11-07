package cmd

import (
	"go-ca/cmd/pki"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Version: "1.0.0",
	Use:     "go_ca",
	Long:    "go-ca is a command line utility for PKI and crypto related operations",
}

func Execute() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	pkiCmd.AddCommand(pki.KeyGenCmd)
	pkiCmd.AddCommand(pki.KeyGenCSRCmd)
	pkiCmd.AddCommand(pki.KeyCertGenCmd)
	pkiCmd.AddCommand(pki.CSRCertGenCmd)
	rootCmd.AddCommand(pkiCmd)

	rootCmd.Execute()
}
