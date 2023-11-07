package pki

import (
	"fmt"
	"go-ca/util"
	"os"

	"github.com/digitorus/pkcs11"
	"github.com/spf13/cobra"
)

var KeyCertGenCmd = &cobra.Command{
	Version: util.Version,
	Use:     "key_cert_gen",
	Short:   "Generates RSA or ECDSA key pair in software (PEM format) or hardware (HSM or Tokens) and selfsigned/delegated certifcate in one go",
	Long: `Generates RSA or ECDSA key pair in software (PEM format) or hardware (HSM or Tokens) and selfsigned/delegated certificate in one go

	RSA key pair generation in software and Root/self signed certificate:-
	./go-ca pki key_cert_gen --key_source=software --key_algo=RSA --key_length=<2048/3072/4096> 
		--private_key_out_path=/home/bilal/data/root_private_key.pem --public_key_out_path=/home/bilal/data/root_public_key.pem
		--common_name=<COMMON_NAME> --organization=<ORGANIZATION> --organization_unit=<ORGANIZATION_UNIT>
		--country=<COUNTRY> --is_ca=true --key_usages=digitalSignature,keyCertSign,cRLSign 
		--cert_out_path=/home/bilal/data/root_cert.pem --duration=20Y

	RSA key pair generation in software and issuing CA certificate:-
	./go-ca pki key_cert_gen --key_source=software --key_algo=RSA --key_length=<2048/3072/4096> 
		--private_key_out_path=/home/bilal/data/issuing_ca_private_key.pem --public_key_out_path=/home/bilal/data/issuing_ca_public_key.pem 
		--common_name=<COMMON_NAME> --organization=<ORGANIZATION> --organization_unit=<ORGANIZATION_UNIT>
		--country=<COUNTRY> --cert_out_path=/home/bilal/data/issuing_ca_cert.pem
		--issuer_private_key_path=/home/bilal/data/root_private_key.pem --issuer_cert_path=/home/bilal/data/root_cert.pem
		--cdp_url=http://goca.com/root.crl --key_usages=digitalSignature,keyCertSign,cRLSign --is_ca=true --duration=10Y

	RSA key pair generation in software and end entity TLS server certificate:-
	./go-ca pki key_cert_gen --key_source=software --key_algo=RSA --key_length=<2048/3072/4096> 
		--private_key_out_path=/home/bilal/data/tls_server_private_key.pem 
		--public_key_out_path=/home/bilal/data/tls_server_public_key.pem 
		--common_name=<COMMON_NAME> --organization=<ORGANIZATION> --organization_unit=<ORGANIZATION_UNIT>
		--country=<COUNTRY> --dns_names=test.com,check.com --cert_out_path=/home/bilal/data/tls_server_cert.pem
		--issuer_private_key_path=/home/bilal/data/issuing_ca_private_key.pem --issuer_cert_path=/home/bilal/data/issuing_ca_cert.pem
		--cdp_url=http://goca.com/issuing_ca.crl --is_ca=false --key_usages=digitalSignature,keyEncipherment
		--ext_key_usages=ServerAuth,ClientAuth --duration=1Y

	Note:- The above commands can use ECDSA algorithm by chaning the --key_algo=ECDSA and --curve=<secp256r1/secp384r1/secp521r1">

	ECDSA key pair generation in hardware and Root/self signed certificate:-	
	./go-ca pki key_cert_gen --key_source=hardware --key_algo=ECDSA --curve=<secp256r1/secp384r1/secp521r1> 
		--pkcs11_module=<pkcs11_module> --pkcs11_slot=<pkcs11_slot> --pkcs11_pin=<pkcs11_pin> --key_id=<cka_id>
		--public_key_out_path=/home/bilal/data/root_public_key.pem --common_name=<COMMON_NAME> --organization=<ORGANIZATION> 
		--organization_unit=<ORGANIZATION_UNIT> --country=<COUNTRY> --cert_out_path=/home/bilal/data/root_cert.pem
		--is_ca=true --key_usages=digitalSignature,keyCertSign,cRLSign --duration=20Y
	
	ECDSA key pair generation in hardware and issuing CA certificate:-	
	./go-ca pki key_cert_gen --key_source=hardware --key_algo=ECDSA --curve=<secp256r1/secp384r1/secp521r1> 
		--pkcs11_module=<pkcs11_module> --pkcs11_slot=<pkcs11_slot> --pkcs11_pin=<pkcs11_pin> --key_id=<cka_id>
		--public_key_out_path=/home/bilal/data/issuing_ca_public_key.pem --common_name=<COMMON_NAME> --organization=<ORGANIZATION> 
		--organization_unit=<ORGANIZATION_UNIT> --country=<COUNTRY> --cert_out_path=/home/bilal/data/issuing_ca_cert.pem
		--issuer_key_id=<cka_id> --issuer_cert_path=/home/bilal/data/root_cert.pem --cdp_url=http://goca.com/root.crl
		--key_usages=digitalSignature,keyCertSign,cRLSign --is_ca=true --duration=10Y
	
	ECDSA key pair generation in hardware and TLS client certificate:-	
	./go-ca pki key_cert_gen --key_source=hardware --key_algo=ECDSA --curve=<secp256r1/secp384r1/secp521r1> 
		--pkcs11_module=<pkcs11_module> --pkcs11_slot=<pkcs11_slot> --pkcs11_pin=<pkcs11_pin> --key_id=<cka_id>
		--public_key_out_path=/home/bilal/data/tls_client_public_key.pem --common_name=<COMMON_NAME> --organization=<ORGANIZATION> 
		--organization_unit=<ORGANIZATION_UNIT> --country=<COUNTRY> --cert_out_path=/home/bilal/data/tls_client_cert.pem
		--issuer_key_id=<cka_id> --issuer_cert_path=/home/bilal/data/issuing_ca_cert.pem --cdp_url=http://goca.com/issuing_ca.crl		
		--is_ca=false --key_usages=digitalSignature,nonRepudiation,keyEncipherment--ext_key_usages=ServerAuth,ClientAuth
		--duration=5Y

	Note:- The above commands can use RSA algorithm by chaning the --key_algo=RSA --key_length=<2048/3072/4096>. For full list of supported subject 
		information values and other options, see flags section.

	`,
	Run: func(cmd *cobra.Command, args []string) {
		var certPEM []byte
		switch keyAlgo.keySource {
		case "software":
			privKey, pubKey, keyAlg, err := generateSoftwareKeyPair()
			if err != nil {
				fmt.Println(fmt.Errorf("%w", err))
				return
			}
			if len(issuerInfo.issuerPvyKeyPath) != 0 {
				privKey, err = getIssuerPrivateKeySoftware(keyAlg)
				if err != nil {
					fmt.Println(fmt.Errorf("%w", err))
					return
				}
			}
			certPEM, err = generateCert(pubKey, keyAlg, privKey)
			if err != nil {
				fmt.Println(fmt.Errorf("unable to generate certificate: %w", err))
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
			_, pubKey, keyAlg, err := generateHardwareKeyPair(context, session)
			if err != nil {
				fmt.Println(fmt.Errorf("%w", err))
				return
			}
			if len(issuerInfo.issuerKeyID) != 0 {
				privKey, err := getIssuerPrivateKeyHardware(context, session, issuerInfo.issuerKeyID)
				if err != nil {
					fmt.Println(fmt.Errorf("%w", err))
					return
				}
				certPEM, err = generateCert(pubKey, keyAlg, privKey)
				if err != nil {
					fmt.Println(fmt.Errorf("unable to generate certificate: %w", err))
					return
				}
			} else {
				privKey, err := getIssuerPrivateKeyHardware(context, session, subjectHardwareKey.keyID)
				if err != nil {
					fmt.Println(fmt.Errorf("%w", err))
					return
				}
				certPEM, err = generateCert(privKey.Public(), keyAlg, privKey)
				if err != nil {
					fmt.Println(fmt.Errorf("unable to generate certificate: %w", err))
					return
				}
			}
		default:
			fmt.Println(fmt.Errorf("invalid key_source: %s", keyAlgo.keySource))
			return
		}
		if len(certOutPath.certOutPath) != 0 {
			err := os.WriteFile(certOutPath.certOutPath, certPEM, 0644)
			if err != nil {
				fmt.Println(fmt.Errorf("unable to write certificate to file: %w", err))
				return
			}
			fmt.Println("certificate file path: " + certOutPath.certOutPath)
		} else {
			fmt.Println(string(certPEM))
		}
	},
}

func init() {
	KeyCertGenCmd.Flags().SortFlags = false

	keyAlgo.addKeyAlgoParams(KeyCertGenCmd)
	p11Module.addP11ModuleParams(KeyCertGenCmd)
	subjectHardwareKey.addSubjectHardwareKeyParams(KeyCertGenCmd)
	subjectInfo.addSubjectInfoParams(KeyCertGenCmd)
	certInfo.addCertInfoParams(KeyCertGenCmd)
	issuerInfo.addIssuerInfoParams(KeyCertGenCmd)
	privKeyOutPath.addPrivKeyOutPathParam(KeyCertGenCmd)
	pubKeyOutPath.addPubKeyOutPathParam(KeyCertGenCmd)
	certOutPath.addCertOutPathParam(KeyCertGenCmd)
}
