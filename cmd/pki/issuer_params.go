package pki

import "github.com/spf13/cobra"

var issuerInfo *issuerInfoParams = &issuerInfoParams{}

type issuerInfoParams struct {
	issuerPvyKeyPath string
	issuerCertPath   string
	issuerKeyID      string
}

func (params *issuerInfoParams) addIssuerInfoParams(cmd *cobra.Command) {
	cmd.Flags().StringVar(&params.issuerPvyKeyPath, "issuer_private_key_path", "", "Path of the issuer private key "+
		"e.g. /home/bilal/issuer_private_key.pem. This param is only applicable if key_source is software. Issuer private key "+
		"must be in PEM format")

	cmd.Flags().StringVar(&params.issuerCertPath, "issuer_cert_path", "", "Path of the issuer certificate "+
		"e.g. /home/bilal/issuer_cert.pem. Issuer certificate must be in PEM format")

	cmd.Flags().StringVar(&params.issuerKeyID, "issuer_key_id", "", "CKAID of the issuer private key in hardware crypto device. "+
		"Required only, if key_source is hardware")
}
