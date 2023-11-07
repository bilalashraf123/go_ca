package cmd

import (
	"github.com/spf13/cobra"
)

var pkiCmd = &cobra.Command{
	Version: "1.0.0",
	Use:     "pki",
	Short:   "Creates software and hardware based PKIs using RSA and ECDSA algorithms",
	Long:    "Creates software and hardware based PKIs using RSA and ECDSA algorithms",
}
