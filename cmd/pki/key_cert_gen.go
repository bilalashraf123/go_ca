package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"go-ca/cert"
	"go-ca/key"
	"go-ca/util"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/digitorus/pkcs11"
	p11 "github.com/miekg/pkcs11"
)

func generateSoftwareKeyPair() (crypto.PrivateKey, crypto.PublicKey, string, error) {
	keyAlg := key.KeyAlgo{
		KeyAlgo:   keyAlgo.keyAlgorithm,
		KeyLength: keyAlgo.keyLength,
		Curve:     keyAlgo.curve,
	}
	privKey, privKeyPEM, pubKeyPEM, err := key.GenerateSoftwareKeyPair(&keyAlg)
	if err != nil {
		return nil, nil, "", fmt.Errorf("unable to generate key pair: %w", err)
	}
	fmt.Println("Key pair generated successfully.")

	if len(privKeyOutPath.privKeyOutPath) != 0 {
		err = os.WriteFile(privKeyOutPath.privKeyOutPath, privKeyPEM, 0644)
		if err != nil {
			return nil, nil, "", fmt.Errorf("unable to write private key to file: %w", err)
		}
		fmt.Println("Private key file path: " + privKeyOutPath.privKeyOutPath)
	} else {
		fmt.Println(string(privKeyPEM))
	}

	if len(pubKeyOutPath.pubKeyOutPath) != 0 {
		err = os.WriteFile(pubKeyOutPath.pubKeyOutPath, pubKeyPEM, 0644)
		if err != nil {
			return nil, nil, "", fmt.Errorf("unable to write public key to file: %w", err)
		}
		fmt.Println("Public key file path: " + pubKeyOutPath.pubKeyOutPath)
	} else {
		fmt.Println(string(pubKeyPEM))
	}
	switch privKey := privKey.(type) {
	case *rsa.PrivateKey:
		return privKey, privKey.Public(), keyAlgo.keyAlgorithm, nil
	case *ecdsa.PrivateKey:
		return privKey, privKey.Public(), keyAlgo.keyAlgorithm, nil
	default:
		return nil, nil, "", fmt.Errorf("inavlid key type")
	}
}

func generateHardwareKeyPair(context *p11.Ctx, session p11.SessionHandle) (crypto.PrivateKey, crypto.PublicKey, string, error) {
	keyAlg := key.KeyAlgo{
		KeyAlgo:   keyAlgo.keyAlgorithm,
		KeyLength: keyAlgo.keyLength,
		Curve:     keyAlgo.curve,
	}
	err := key.GenerateHardwareKeyPair(context, session, &keyAlg, subjectHardwareKey.keyID)
	if err != nil {
		return nil, nil, "", fmt.Errorf("unable to generate key pair: %w", err)
	}
	fmt.Println("Key pair generated successfully.")

	publicKey, err := pkcs11.GetPublic(context, session, []byte(subjectHardwareKey.keyID))
	if err != nil {
		return nil, nil, "", fmt.Errorf("unable to get public key: %w", err)
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, nil, "", fmt.Errorf("%w", err)
	}
	publicKeyPEMBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKeyBytes,
		},
	)
	if len(pubKeyOutPath.pubKeyOutPath) != 0 {
		err = os.WriteFile(pubKeyOutPath.pubKeyOutPath, publicKeyPEMBytes, 0644)
		if err != nil {
			return nil, nil, "", fmt.Errorf("unable to write public key to file: %w", err)
		}
		fmt.Println("Public key file path: " + pubKeyOutPath.pubKeyOutPath)
	} else {
		fmt.Println(string(publicKeyPEMBytes))
	}
	privKey, err := pkcs11.InitPrivateKey(context, session, []byte(subjectHardwareKey.keyID))
	if err != nil {
		return nil, nil, "", fmt.Errorf("unable to initialize private key for signing")
	}
	return privKey, privKey.Public(), keyAlgo.keyAlgorithm, nil
}

func getIssuerPrivateKeySoftware(keyAlg string) (crypto.PrivateKey, error) {
	var privKey crypto.PrivateKey
	keyData, err := os.ReadFile(issuerInfo.issuerPvyKeyPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read issuer private key file: %w", err)
	}
	switch keyAlg {
	case "RSA":
		block, _ := pem.Decode(keyData)
		if block == nil || block.Type != "RSA PRIVATE KEY" {
			return nil, fmt.Errorf("failed to decode PEM block containing RSA private key")
		}
		privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse RSA private key: %w", err)
		}
	case "ECDSA":
		block, _ := pem.Decode(keyData)
		if block == nil || block.Type != "EC PRIVATE KEY" {
			return nil, fmt.Errorf("failed to decode PEM block containing EC private key")
		}
		privKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse ECDSA private key: %w", err)
		}
	}
	return privKey, nil
}

func getIssuerPrivateKeyHardware(context *p11.Ctx, session p11.SessionHandle, keyID string) (*pkcs11.PrivateKey, error) {
	privKey, err := pkcs11.InitPrivateKey(context, session, []byte(keyID))
	if err != nil {
		return nil, fmt.Errorf("unable to get issuer private key handle: %w", err)
	}
	return privKey, nil
}

func generateCert(subPubKey crypto.PublicKey, keyAlgo string, issuerPvtKey crypto.PrivateKey) ([]byte, error) {
	SubjectInfo := createSubjectInfo()

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("unable to generate certificate serial number: %w", err)
	}
	notBefore, notAfter, err := calculateValidity(certInfo.duration)
	if err != nil {
		return nil, fmt.Errorf("unable to calculate certificate validity: %w", err)
	}
	certManager, err := cert.CreateX509Certificate(SubjectInfo, subPubKey, serialNumber)
	if err != nil {
		return nil, fmt.Errorf("unable to create X509 certificate object: %w", err)
	}
	err = certManager.SetValidityInfo(notBefore, notAfter)
	if err != nil {
		return nil, fmt.Errorf("unable to set validity for certificate: %w", err)
	}
	if len(certInfo.keyUsages) != 0 {
		keyUsages := strings.Split(certInfo.keyUsages, ",")
		err := certManager.SetKeyUsages(keyUsages)
		if err != nil {
			return nil, fmt.Errorf("unable to set key usages for certificate: %w", err)
		}
	}
	if len(certInfo.extendedKeyUsages) != 0 {
		extKeyUsages := strings.Split(certInfo.extendedKeyUsages, ",")
		err := certManager.SetExtendedKeyUsages(extKeyUsages, false)
		if err != nil {
			return nil, fmt.Errorf("unable to set extended key usages: %w", err)
		}
	}
	if len(issuerInfo.issuerCertPath) != 0 {
		issuerCertFile, err := os.ReadFile(issuerInfo.issuerCertPath)
		if err != nil {
			return nil, fmt.Errorf("unable to read issuer certificate file path: %w", err)
		}
		block, _ := pem.Decode(issuerCertFile)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("failed to decode PEM block containing X509 certificate")
		}
		caCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse X509 certificate: %w", err)
		}
		err = certManager.SetAKI(caCert.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("unable to set AKI: %w", err)
		}
		certManager.SetIssuerCertificate(caCert)
	} else {
		err := certManager.SetAKI(subPubKey)
		if err != nil {
			return nil, fmt.Errorf("unable to set AKI %w", err)
		}
	}
	err = certManager.SetSKI(subPubKey)
	if err != nil {
		return nil, fmt.Errorf("unable to set SKI: %w", err)
	}
	if len(certInfo.cdpURL) != 0 {
		err := certManager.SetCDPs([]string{certInfo.cdpURL})
		if err != nil {
			return nil, fmt.Errorf("unable to set CDP extension: %w", err)
		}
	}
	if len(certInfo.aiaCertIssuerURL) != 0 {
		err := certManager.SetAIACertIssuers([]string{certInfo.aiaCertIssuerURL})
		if err != nil {
			return nil, fmt.Errorf("unable to set AIA cert issuer: %w", err)
		}
	}
	if len(certInfo.aiaOcspURL) != 0 {
		err := certManager.SetAIAOCSPs([]string{certInfo.aiaOcspURL})
		if err != nil {
			return nil, fmt.Errorf("unable to set AIA OCSP: %w", err)
		}
	}
	if len(certInfo.certPolicy) != 0 {
		policyInfo := strings.Split(certInfo.certPolicy, ",")
		var policyInfoCert cert.PolicyInfo
		policyInfoCert.PolicyOID = policyInfo[0]
		if len(policyInfo) != 2 {
			policyInfoCert.CpsURI = policyInfo[1]
		}
		if len(policyInfo) != 3 {
			policyInfoCert.UserNotice = policyInfo[2]
		}
		err := certManager.SetCertificatePolicies([]cert.PolicyInfo{policyInfoCert}, false)
		if err != nil {
			return nil, fmt.Errorf("unable to set certificate policies extension: %w", err)
		}
	}
	certManager.SetBasicConstraints(certInfo.isCA, -1)

	if len(subjectInfo.dnsNames) != 0 {
		dnsNames := strings.Split(subjectInfo.dnsNames, ",")
		err := certManager.SetSubjectAltNameDNSName(dnsNames)
		if err != nil {
			return nil, fmt.Errorf("unable to set SAN DNS name(s): %w", err)
		}
	}
	if len(subjectInfo.emailAddress) != 0 {
		err := certManager.SetSubjectAltNameEmail([]string{subjectInfo.emailAddress})
		if err != nil {
			return nil, fmt.Errorf("unable to set SAN email address(es): %w", err)
		}
	}
	signatureAlgo, err := getSignatureAlgorithm(keyAlgo, "sha384")
	if err != nil {
		return nil, fmt.Errorf("unable to get signature algorithm: %w", err)
	}
	pemCert, err := certManager.Sign(signatureAlgo, issuerPvtKey)
	if err != nil {
		return nil, fmt.Errorf("unable to sign certificate: %w", err)
	}
	return []byte(pemCert), nil
}

func getSignatureAlgorithm(keyType string, digestAlgorithm string) (x509.SignatureAlgorithm, error) {
	switch keyType {
	case "RSA":
		switch digestAlgorithm {
		case "sha256":
			return x509.SHA256WithRSA, nil
		case "sha384":
			return x509.SHA384WithRSA, nil
		case "sha512":
			return x509.SHA512WithRSA, nil
		default:
			return -1, fmt.Errorf("invalid digest algorithm: %s", digestAlgorithm)
		}
	case "ECDSA":
		switch digestAlgorithm {
		case "sha256":
			return x509.ECDSAWithSHA256, nil
		case "sha384":
			return x509.ECDSAWithSHA384, nil
		case "sha512":
			return x509.ECDSAWithSHA512, nil
		default:
			return -1, fmt.Errorf("invalid digest algorithm: %s", digestAlgorithm)
		}
	default:
		return -1, fmt.Errorf("invalid key type: %s", keyType)
	}
}

func generateSerialNumber() (*big.Int, error) {
	randBytes := make([]byte, 15)
	_, err := rand.Read(randBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to generate random bytes for serial number: %w", err)
	}
	serialNumber := new(big.Int)
	serialNumber.SetBytes(randBytes)
	return serialNumber, nil
}

func calculateValidity(validity string) (time.Time, time.Time, error) {
	var durationStr string
	var unit string
	unit = validity[len(validity)-2:]
	if unit == "MO" {
		durationStr = validity[:len(validity)-2]
	} else {
		unit = validity[len(validity)-1:]
		durationStr = validity[:len(validity)-1]
	}
	duration, err := strconv.ParseInt(durationStr, 10, 64)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("unable to parse duration: %w", err)
	}
	notBefore := time.Now()
	var notAfter time.Time

	switch unit {
	case "Y":
		notAfter = notBefore.AddDate(int(duration), 0, 0)
	case "MO":
		notAfter = notBefore.AddDate(0, int(duration), 0)
	case "D":
		notAfter = notBefore.AddDate(0, 0, int(duration))
	case "H":
		notAfter = notBefore.Add(time.Hour * time.Duration(duration))
	case "M":
		notAfter = notBefore.Add(time.Minute * time.Duration(duration))
	case "S":
		notAfter = notBefore.Add(time.Second * time.Duration(duration))
	default:
		return time.Time{}, time.Time{}, fmt.Errorf("invalid duration unit: %s", unit)
	}
	return notBefore, notAfter, nil
}

func createSubjectInfo() *util.SubjectInfo {
	subject := &util.SubjectInfo{}
	if len(subjectInfo.commonName) != 0 {
		subject.CommonName = subjectInfo.commonName
	}
	if len(subjectInfo.givenName) != 0 {
		subject.GivenName = subjectInfo.givenName
	}
	if len(subjectInfo.surname) != 0 {
		subject.Surname = subjectInfo.surname
	}
	if len(subjectInfo.organization) != 0 {
		subject.Organization = subjectInfo.organization
	}
	if len(subjectInfo.organizationUnit) != 0 {
		subject.OrganizationalUnit = subjectInfo.organizationUnit
	}
	if len(subjectInfo.country) != 0 {
		subject.Country = subjectInfo.country
	}
	if len(subjectInfo.stateOrProvince) != 0 {
		subject.StateOrProvince = subjectInfo.stateOrProvince
	}
	return subject
}
