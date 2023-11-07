package pki

import "github.com/spf13/cobra"

var subjectInfo *subjectInfoParams = &subjectInfoParams{}
var subjectHardwareKey *subjectHardwareKeyParams = &subjectHardwareKeyParams{}

type subjectInfoParams struct {
	commonName       string
	givenName        string
	surname          string
	organization     string
	organizationUnit string
	country          string
	stateOrProvince  string
	dnsNames         string
	emailAddress     string
}

func (params *subjectInfoParams) addSubjectInfoParams(cmd *cobra.Command) {
	cmd.Flags().StringVar(&params.commonName, "common_name", "", "Subject common name")
	cmd.Flags().StringVar(&params.givenName, "given_name", "", "Subject given name")
	cmd.Flags().StringVar(&params.surname, "surnamename", "", "Subject surname")
	cmd.Flags().StringVar(&params.organization, "organization", "", "Subject organization")
	cmd.Flags().StringVar(&params.organizationUnit, "organization_unit", "", "Subject organization unit")
	cmd.Flags().StringVar(&params.country, "country", "", "Subject country")
	cmd.Flags().StringVar(&params.stateOrProvince, "state_or_province", "", "Subject state or province")
	cmd.Flags().StringVar(&params.dnsNames, "dns_names", "", "Comma separated list of DNS names")
	cmd.Flags().StringVar(&params.emailAddress, "email_address", "", "Email address")
}

type subjectHardwareKeyParams struct {
	keyID string
}

func (params *subjectHardwareKeyParams) addSubjectHardwareKeyParams(cmd *cobra.Command) {
	cmd.Flags().StringVar(&params.keyID, "key_id", "", "CKAID of the to be generated key pair in hardware crypto device."+
		"Required only, if key_source is hardware.")
}
