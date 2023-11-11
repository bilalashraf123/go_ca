package cmd

import (
	"go-ca/cmd/pki"
	"go-ca/cmd/timestamp"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Version: "1.0.0",
	Use:     "go_ca",
	Long:    "go-ca is a command line utility for PKI and crypto related operations",
}

func Execute() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	pki.PKICmd.AddCommand(pki.KeyGenCmd)
	pki.PKICmd.AddCommand(pki.KeyGenCSRCmd)
	pki.PKICmd.AddCommand(pki.KeyCertGenCmd)
	pki.PKICmd.AddCommand(pki.CSRCertGenCmd)
	rootCmd.AddCommand(pki.PKICmd)

	rootCmd.AddCommand(timestamp.TimestampCmd)

	rootCmd.Execute()
}
