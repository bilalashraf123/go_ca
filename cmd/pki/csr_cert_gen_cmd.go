package pki

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"go-ca/csr"
	"go-ca/util"
	"os"

	"github.com/digitorus/pkcs11"
	"github.com/spf13/cobra"
)

var CSRCertGenCmd = &cobra.Command{
	Version: util.Version,
	Use:     "csr_cert_gen",
	Short:   "Generates certificate using software/hardware CA key by providing CSR and subject information as an input",
	Long: `Generates certificate using software/hardware CA key by providing CSR and subject information as an input

	Issuing CA certificate generation using RSA CA key in software:-
	./go-ca pki csr_cert_gen --common_name=<COMMON_NAME> --organization=<ORGANIZATION> --organization_unit=<ORGANIZATION_UNIT>
		--country=<COUNTRY> --cert_out_path=/home/bilal/data/issuing_ca_cert.pem
		--issuer_private_key_path=/home/bilal/data/root_private_key.pem --issuer_cert_path=/home/bilal/data/root_cert.pem
		--cdp_url=http://goca.com/root.crl --csr_input_path=/home/bilal/data/csr.pem --duration=10Y

	TLS server certificate generation using RSA CA key in software:-
	./go-ca pki csr_cert_gen --common_name=<COMMON_NAME> --organization=<ORGANIZATION> --organization_unit=<ORGANIZATION_UNIT>
		--country=<COUNTRY> --dns_names=test.com,check.com --cert_out_path=/home/bilal/data/tls_server_cert.pem
		--issuer_private_key_path=/home/bilal/data/issuing_ca_private_key.pem --issuer_cert_path=/home/bilal/data/issuing_ca_cert.pem
		--cdp_url=http://goca.com/issuing_ca.crl --csr_input_path=/home/bilal/data/csr.pem --duration=1Y

	Note:- The above commands can also be used if CSR is signed using ECDSA algorithm and issuer key and certificate also uses
	ECDSA algorithm.

	Issuing CA certificate generation using ECDSA CA key in hardware:-
	./go-ca pki csr_cert_gen --pkcs11_module=<pkcs11_module> --pkcs11_slot=<pkcs11_slot> --pkcs11_pin=<pkcs11_pin>
		--common_name=<COMMON_NAME> --organization=<ORGANIZATION> --organization_unit=<ORGANIZATION_UNIT> 
		--country=<COUNTRY> --cert_out_path=/home/bilal/data/issuing_ca_cert.pem --csr_input_path=/home/data/bilal/csr.pem
		--issuer_private_key_id=<cka_id> --issuer_cert_path=/home/bilal/data/root_cert.pem --cdp_url=http://goca.com/root.crl
		--duration=10Y

	TLS client certificate generation using ECDSA CA key in hardware:-
	./go-ca pki csr_cert_gen --pkcs11_module=<pkcs11_module> --pkcs11_slot=<pkcs11_slot> --pkcs11_pin=<pkcs11_pin> 
		--common_name=<COMMON_NAME> --organization=<ORGANIZATION> --organization_unit=<ORGANIZATION_UNIT> 
		--country=<COUNTRY> --cert_out_path=/home/bilal/data/tls_client_cert.pem --csr_input_path=/home/bilal/data/csr.pem
		--issuer_private_key_id=<cka_id> --issuer_cert_path=/home/bilal/data/issuing_ca_cert.pem 
		--cdp_url=http://goca.com/issuing_ca.crl --duration=5Y		
	
	Note:- For full list of supported subject information values and other options, see flags section.

	`,
	Run: func(cmd *cobra.Command, args []string) {
		csrPEM, err := os.ReadFile(csrInputPath.csrInputPath)
		if err != nil {
			fmt.Println(fmt.Errorf("unable to read issuer private key file: %w", err))
			return
		}
		csr, err := csr.ParseCSR(string(csrPEM))
		if err != nil {
			fmt.Println(fmt.Errorf("unable to parse CSR: %w", err))
			return
		}
		err = csr.VerifySignature()
		if err != nil {
			fmt.Println(fmt.Errorf("unable to verify CSR signature: %w", err))
			return
		}
		pubKey := csr.GetPublicKey()

		var keyAlg string
		switch pubKey.(type) {
		case *rsa.PublicKey:
			keyAlg = "RSA"
		case *ecdsa.PublicKey:
			keyAlg = "ECDSA"
		default:
			fmt.Println(fmt.Errorf("invalid/unsupported key algorithm: %s", keyAlg))
		}
		var certPEM []byte
		if len(issuerInfo.issuerPvyKeyPath) != 0 {
			issuerPrivKey, err := getIssuerPrivateKeySoftware(keyAlg)
			if err != nil {
				fmt.Println(fmt.Errorf("unable to get issuer private key: %w", err))
				return
			}
			certPEM, err = generateCert(pubKey, keyAlg, issuerPrivKey)
			if err != nil {
				fmt.Println(fmt.Errorf("unable to generate certificate: %w", err))
				return
			}
		} else {
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
			issuerPrivKey, err := getIssuerPrivateKeyHardware(context, session, issuerInfo.issuerKeyID)
			if err != nil {
				fmt.Println(fmt.Errorf("unable to get issuer private key: %w", err))
				return
			}
			certPEM, err = generateCert(pubKey, keyAlg, issuerPrivKey)
			if err != nil {
				fmt.Println(fmt.Errorf("unable to generate certificate: %w", err))
				return
			}
		}
		if len(certOutPath.certOutPath) != 0 {
			err = os.WriteFile(certOutPath.certOutPath, certPEM, 0644)
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

	subjectInfo.addSubjectInfoParams(CSRCertGenCmd)
	certInfo.addCertInfoParams(CSRCertGenCmd)
	p11Module.addP11ModuleParams(CSRCertGenCmd)
	issuerInfo.addIssuerInfoParams(CSRCertGenCmd)
	csrInputPath.addCSRInputPathParam(CSRCertGenCmd)
	certOutPath.addCertOutPathParam(CSRCertGenCmd)
}
