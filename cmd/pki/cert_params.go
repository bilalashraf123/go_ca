package pki

import "github.com/spf13/cobra"

var certInfo *certInfoParams = &certInfoParams{}

type certInfoParams struct {
	duration          string
	cdpURL            string
	aiaOcspURL        string
	aiaCertIssuerURL  string
	certPolicy        string
	isCA              bool
	keyUsages         string
	extendedKeyUsages string
}

func (params *certInfoParams) addCertInfoParams(cmd *cobra.Command) {
	cmd.Flags().StringVar(&params.duration, "duration", "", "Certication duration. Possible values are 1Y or 2MO or 3D "+
		"or 6H or 4M or 5S.")
	cmd.MarkFlagRequired("duration")

	cmd.Flags().StringVar(&params.cdpURL, "cdp_url", "", "CRL URL to add in the certificate")

	cmd.Flags().StringVar(&params.aiaOcspURL, "ocsp_url", "", "URL of the OCSP server to add in the certificate")

	cmd.Flags().StringVar(&params.aiaCertIssuerURL, "cert_issuer_url", "", "CA certificate URL to add in the certificate")

	cmd.Flags().StringVar(&params.certPolicy, "cert_policy", "", "Certificate policy to add in the certificate. Certificate policy "+
		"must of format <POLICY_OID>,<CPS_URI>,<USER_NOTICE>. CPS_URI and USER_NOTICE is optional.")

	cmd.Flags().BoolVar(&params.isCA, "is_ca", false, "It specifies whether the to be issued certificate is of "+
		"type CA or end entity")

	cmd.Flags().StringVar(&params.keyUsages, "key_usages", "", "Key usages to add in the certificate. Possible values are "+
		"digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign, encipherOnly "+
		"and decipherOnly. Multiple values must be  , separated e.g. digitalSignature,keyCertSign,cRLSign and so on.")

	cmd.Flags().StringVar(&params.extendedKeyUsages, "ext_key_usages", "", "Extended Key usages to add in the certificate. "+
		"Possible values are Any, ServerAuth, ClientAuth, CodeSigning, EmailProtection, TimeStamping, OCSPSigning "+
		"and <CUSTOM_OID>. Custom OID is of the form 1.3.6.1.5.5.7.3.7. Multiple values must be  , separated e.g. "+
		"ClientAuth,EmailProtection and so on.")
}
