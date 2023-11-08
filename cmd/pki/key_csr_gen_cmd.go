package pki

import (
	"fmt"
	"go-ca/csr"
	"go-ca/util"
	"os"

	"github.com/digitorus/pkcs11"
	"github.com/spf13/cobra"
)

var KeyGenCSRCmd = &cobra.Command{
	Version: util.Version,
	Use:     "key_csr_gen",
	Short:   "Generates RSA or ECDSA key pair in software (PEM format) or hardware (HSM or Tokens) and CSR in one go",
	Long: `Generates RSA or ECDSA key pair in software (PEM format) or hardware (HSM or Tokens) and CSR in one go

	RSA key pair generation in software and CSR:-
	./go-ca pki key_csr_gen --key_source=software --key_algo=RSA --key_length=<2048/3072/4096> --private_key_out_path=/home/bilal/data/private_key.pem 
		--public_key_out_path=/home/bilal/data/public_key.pem --csr_out_path=/home/bilal/data/csr.pem
	
	ECDSA key pair generation in software:-
	./go-ca pki key_csr_gen --key_source=software --key_algo=ECDSA --curve=<secp256r1/secp384r1/secp521r1> --private_key_out_path=/home/bilal/data/private_key.pem 
		--public_key_out_path=/home/bilal/data/public_key.pem --csr_out_path=/home/bilal/data/csr.pem

	RSA key pair generation in hardware and CSR:-	
	./go-ca pki key_csr_gen --key_source=hardware --key_algo=RSA --key_length=<2048/3072/4096> --pkcs11_module=<pkcs11_module> --pkcs11_slot=<pkcs11_slot> 
		--key_id=<cka_id> --pkcs11_pin=<pkcs11_pin> --public_key_out_path=/home/bilal/data/public_key.pem 
		--csr_out_path=/home/bilal/data/csr.pem
	
	ECDSA key pair generation in hardware:-	
	./go-ca pki key_csr_gen --key_source=hardware --key_algo=ECDSA --curve=<secp256r1/secp384r1/secp521r1> --pkcs11_module=<pkcs11_module> --pkcs11_slot=<pkcs11_slot> 
		--key_id=<cka_id> --pkcs11_pin=<pkcs11_pin> --public_key_out_path=/home/bilal/data/public_key.pem 
		--csr_out_path=/home/bilal/data/csr.pem
	
	RSA key pair generation in software and CSR without private, public and CSR out path:-	
	./go-ca pki key_csr_gen --key_source=software --key_algo=RSA --key_length=<2048/3072/4096>
 	
	`,
	Run: func(cmd *cobra.Command, args []string) {
		err := validateKeyGenParams()
		if err != nil {
			fmt.Println(fmt.Errorf("%w", err))
			return
		}
		SubjectInfo := &util.SubjectInfo{
			CommonName: "goCA generated CSR",
		}
		sigAlgo, err := getSignatureAlgorithm(keyAlgo.keyAlgorithm, "sha384")
		if err != nil {
			fmt.Println("%w", err)
			return
		}

		var CSRPEM string
		switch keyAlgo.keySource {
		case "software":
			privKey, pubKey, _, err := generateSoftwareKeyPair()
			if err != nil {
				fmt.Println(fmt.Errorf("%w", err))
				return
			}
			csrManager, err := csr.CreateCSR(SubjectInfo, pubKey)
			if err != nil {
				fmt.Println(fmt.Errorf("unable to create CSR using software key: %w", err))
				return
			}
			CSRPEM, err = csrManager.Sign(sigAlgo, privKey)
			if err != nil {
				fmt.Println(fmt.Errorf("unable to sign CSR using software key: %w", err))
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
			privateKey, err := pkcs11.InitPrivateKey(context, session, []byte(subjectHardwareKey.keyID))
			if err != nil {
				fmt.Println(fmt.Errorf("unable to get issuer private key handle: %w", err))
				return
			}
			csrManager, err := csr.CreateCSR(SubjectInfo, privateKey.Public())
			if err != nil {
				fmt.Println(fmt.Errorf("unable to create CSR using hardware key: %w", err))
				return
			}
			CSRPEM, err = csrManager.Sign(sigAlgo, privateKey)
			if err != nil {
				fmt.Println(fmt.Errorf("unable to sign CSR using hardware key: %w", err))
				return
			}
		default:
			fmt.Println(fmt.Errorf("invalid key_source: %s", keyAlgo.keySource))
			return
		}
		if len(csrOutPath.csrOutPath) != 0 {
			err = os.WriteFile(csrOutPath.csrOutPath, []byte(CSRPEM), 0644)
			if err != nil {
				fmt.Println(fmt.Errorf("unable to write CSR to file: %w", err))
			}
			fmt.Println("CSR file path: " + csrOutPath.csrOutPath)
		} else {
			fmt.Println(string(CSRPEM))
		}
	},
}

func init() {
	KeyGenCSRCmd.Flags().SortFlags = false

	keyAlgo.addKeyAlgoParams(KeyGenCSRCmd)
	p11Module.addP11ModuleParams(KeyGenCSRCmd)
	subjectHardwareKey.addSubjectHardwareKeyParams(KeyGenCSRCmd)
	privKeyOutPath.addPrivKeyOutPathParam(KeyGenCSRCmd)
	pubKeyOutPath.addPubKeyOutPathParam(KeyGenCSRCmd)
	csrOutPath.addCSROutPathParam(KeyGenCSRCmd)
}
