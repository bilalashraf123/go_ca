package pki

import (
	"github.com/spf13/cobra"
)

var keyAlgo *keyAlgoParams = &keyAlgoParams{}
var privKeyOutPath *privateKeyOutPathParams = &privateKeyOutPathParams{}
var pubKeyOutPath *publicKeyOutPathParams = &publicKeyOutPathParams{}
var csrOutPath *csrOutPathParams = &csrOutPathParams{}
var p11Module *p11ModuleParams = &p11ModuleParams{}
var certOutPath *certOutPathParams = &certOutPathParams{}
var csrInputPath *csrInputPathParams = &csrInputPathParams{}

type keyAlgoParams struct {
	keySource    string
	keyAlgorithm string
	keyLength    int
	curve        string
}

func (params *keyAlgoParams) addKeyAlgoParams(cmd *cobra.Command) {
	cmd.Flags().StringVar(&params.keySource, "key_source", "", "Key generation source. Possible values are software "+
		"(key pair in PEM format) or hardware (key pair in HSM or USB token)")
	cmd.MarkFlagRequired("key_source")

	cmd.Flags().StringVar(&params.keyAlgorithm, "key_algo", "", "Key generation algorithm. Possible values are RSA or ECDSA")
	cmd.MarkFlagRequired("key_algo")

	cmd.Flags().IntVar(&params.keyLength, "key_length", -1, "Key length. Only applicable if the key_algo parameter"+
		"is RSA. Possible values are 2048, 3072 and 4096")

	cmd.Flags().StringVar(&params.curve, "curve", "", "Key curve. Only applicable if the key_algo parameter"+
		"is ECDSA. Possible values are secp256r1, secp384r1 or secp521r1")
}

type p11ModuleParams struct {
	pkcs11Module string
	slot         int
	pin          string
}

func (params *p11ModuleParams) addP11ModuleParams(cmd *cobra.Command) {
	cmd.Flags().StringVar(&params.pkcs11Module, "pkcs11_module", "", "Name of the PKCS#11 module e.g. /usr/lib/softhsm/libsofthsm2.so. "+
		"Required only if key_source is hardware.")

	cmd.Flags().IntVar(&params.slot, "pkcs11_slot", -1, "PKCS#11 slot. Required only, if key_source is hardware.")

	cmd.Flags().StringVar(&params.pin, "pkcs11_pin", "", "PKCS#11 PIN. Required only, if key_source is hardware.")

}

type privateKeyOutPathParams struct {
	privKeyOutPath string
}

func (params *privateKeyOutPathParams) addPrivKeyOutPathParam(cmd *cobra.Command) {
	cmd.Flags().StringVar(&params.privKeyOutPath, "private_key_out_path", "", "Path where generated private key will be written "+
		"e.g. /home/bilal/private_key.pem. If no output path is provided, it will print the private key to console. This param is "+
		"only applicable if key_source is software")
}

type publicKeyOutPathParams struct {
	pubKeyOutPath string
}

func (params *publicKeyOutPathParams) addPubKeyOutPathParam(cmd *cobra.Command) {
	cmd.Flags().StringVar(&params.pubKeyOutPath, "public_key_out_path", "", "Path where generated public key will be written "+
		"e.g. /home/bilal/public_key.pem. If no output path is provided, it will print the public key to console")
}

type csrOutPathParams struct {
	csrOutPath string
}

func (params *csrOutPathParams) addCSROutPathParam(cmd *cobra.Command) {
	cmd.Flags().StringVar(&params.csrOutPath, "csr_out_path", "", "Path where generated CSR will be written "+
		"e.g. /home/bilal/csr.pem. If no output path is provided, it will print the CSR to the console")
}

type csrInputPathParams struct {
	csrInputPath string
}

func (params *csrInputPathParams) addCSRInputPathParam(cmd *cobra.Command) {
	cmd.Flags().StringVar(&params.csrInputPath, "csr_input_path", "", "CSR input path e.g. /home/bilal/csr.pem.")
}

type certOutPathParams struct {
	certOutPath string
}

func (params *certOutPathParams) addCertOutPathParam(cmd *cobra.Command) {
	cmd.Flags().StringVar(&params.certOutPath, "cert_out_path", "", "Path where generated certificate will be written "+
		"e.g. /home/bilal/cert.pem. If no output path is provided, it will print the certificate to the console")
}
