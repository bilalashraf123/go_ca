package pki

import (
	"fmt"
	"go-ca/util"

	"github.com/digitorus/pkcs11"
	"github.com/spf13/cobra"
)

var KeyGenCmd = &cobra.Command{
	Version: util.Version,
	Use:     "key_gen",
	Short:   "Generates RSA or ECDSA key pair in software (PEM format) or hardware (HSM or Tokens)",
	Long: `Generates RSA or ECDSA key pair in software (PEM format) or hardware (HSM or Tokens)
 
	RSA key pair generation in software:-
	./go-ca pki key_gen --key_source=software --key_algo=RSA --key_length=<2048/3072/4096> --private_key_out_path=/home/bilal/data/private_key.pem 
		--public_key_out_path=/home/bilal/data/public_key.pem
	
	ECDSA key pair generation in software:-
	./go-ca pki key_gen --key_source=software --key_algo=ECDSA --curve=<secp256r1/secp384r1/secp521r1> --private_key_out_path=/home/bilal/data/private_key.pem 
		--public_key_out_path=/home/bilal/data/public_key.pem

	RSA key pair generation in software without private and public key output path:-
	./go-ca pki key_gen --key_source=software --key_algo=RSA --key_length=<2048/3072/4096>

	RSA key pair generation in hardware:-
	./go-ca pki key_gen --key_source=hardware --key_algo=RSA --key_length=<2048/3072/4096> --pkcs11_module=<pkcs11_module> --pkcs11_slot=<pkcs11_slot> 
		--key_id=<cka_id> --pkcs11_pin=<pkcs11_pin> --public_key_out_path=/home/bilal/data/public_key.pem
	
	ECDSA key pair generation in hardware:-
	./go-ca pki key_gen --key_source=hardware --key_algo=ECDSA --curve=<secp256r1/secp384r1/secp521r1> --pkcs11_module=<pkcs11_module> --pkcs11_slot=<pkcs11_slot> 
		--key_id=<cka_id> --pkcs11_pin=<pkcs11_pin> --public_key_out_path=/home/bilal/data/public_key.pem

	RSA key pair generation in hardware without public key output path:-
	./go-ca pki key_gen --key_source=hardware --key_algo=RSA --key_length=<2048/3072/4096> --pkcs11_module=<pkcs11_module> --pkcs11_slot=<pkcs11_slot> 
		--key_id=<cka_id> --pkcs11_pin=<pkcs11_pin>
	
	`,
	Run: func(cmd *cobra.Command, args []string) {
		switch keyAlgo.keySource {
		case "software":
			_, _, _, err := generateSoftwareKeyPair()
			if err != nil {
				fmt.Println(fmt.Errorf("%w", err))
				return
			}
		case "hardware":
			context := pkcs11.New(p11Module.pkcs11Module)
			if context == nil {
				fmt.Println(fmt.Errorf("failed to load pkcs11 module %s", p11Module.pkcs11Module))
				return
			}
			defer context.Destroy()
			defer context.Finalize()

			err := context.Initialize()
			if err != nil {
				fmt.Println(fmt.Errorf("unable to initializa PKCS#11 context: %w", err))
				return
			}
			session, err := pkcs11.CreateSession(context, uint(p11Module.slot), p11Module.pin, true)
			if err != nil {
				fmt.Println(fmt.Errorf("unable to open PKCS#11 session: %w", err))
				return
			}
			_, _, _, err = generateHardwareKeyPair(context, session)
			if err != nil {
				fmt.Println(fmt.Errorf("%w", err))
				return
			}
		default:
			fmt.Println(fmt.Errorf("invalid key_source: %s", keyAlgo.keySource))
			return
		}
	},
}

func init() {
	KeyGenCmd.Flags().SortFlags = false

	keyAlgo.addKeyAlgoParams(KeyGenCmd)
	p11Module.addP11ModuleParams(KeyGenCmd)
	subjectHardwareKey.addSubjectHardwareKeyParams(KeyGenCmd)
	privKeyOutPath.addPrivKeyOutPathParam(KeyGenCmd)
	pubKeyOutPath.addPubKeyOutPathParam(KeyGenCmd)
}
