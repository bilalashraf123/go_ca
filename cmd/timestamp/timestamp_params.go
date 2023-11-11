package timestamp

import "github.com/spf13/cobra"

var tsParams *timestampParams = &timestampParams{}

type timestampParams struct {
	digestAlgo     string
	tsaPolicyOID   string
	tsaServerURL   string
	tsaUserName    string
	tsaPassword    string
	inputFilePath  string
	tokenOutPath   string
	tsaCertOutPath string
}

func (params *timestampParams) addTimestampParams(cmd *cobra.Command) {
	cmd.Flags().StringVar(&params.digestAlgo, "digest_algo", "", "Message imprint digest algorithm. Possible values are sha256, "+
		"sha384 or sha512")
	cmd.MarkFlagRequired("digest_algo")

	cmd.Flags().StringVar(&params.tsaPolicyOID, "tsa_policy_id", "", "TSA Policy ID, if TSA requires for it")

	cmd.Flags().StringVar(&params.tsaServerURL, "tsa_server_url", "", "TSA server URL")
	cmd.MarkFlagRequired("tsa_server_url")

	cmd.Flags().StringVar(&params.inputFilePath, "input_file_path", "", "Path of the file containing data to timestamp")
	cmd.MarkFlagRequired("input_file_path")

	cmd.Flags().StringVar(&params.tsaUserName, "tsa_username", "", "TSA username if TSA server expects HTTP basic authentication")

	cmd.Flags().StringVar(&params.tsaPassword, "tsa_password", "", "TSA password if TSA server expects HTTP basic authentication")

	cmd.Flags().StringVar(&params.tokenOutPath, "token_out_path", "", "Path on which returned timestamp token is to be written e.g. "+
		"/home/bilal/data/token.der")
	cmd.MarkFlagRequired("token_out_path")

	cmd.Flags().StringVar(&params.tsaCertOutPath, "tsa_cert_out_path", "", "Path on which returned TSA certificate is to be written e.g. "+
		"/home/bilal/data/tsa_cert.pem")
}
