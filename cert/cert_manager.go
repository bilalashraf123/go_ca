package cert

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"go-ca/util"
	"math/big"
	"time"
)

type CertManager struct {
	x509Cert   *x509.Certificate
	issuerCert *x509.Certificate
}

func CreateX509Certificate(subject *util.SubjectInfo, publicKey crypto.PublicKey, serialNumber *big.Int) (*CertManager, error) {
	if subject == nil {
		return nil, fmt.Errorf("subject information must be provided")
	}
	var cert x509.Certificate

	subjectName, err := util.CreateSubject(subject)
	if err != nil {
		return nil, fmt.Errorf("unable to create pkix subject name: %w", err)
	}
	cert.Subject = subjectName
	cert.PublicKey = publicKey
	cert.SerialNumber = serialNumber
	return &CertManager{
		x509Cert: &cert,
	}, nil
}

func (cert *CertManager) SetValidityInfo(notBefore time.Time, notAfter time.Time) error {
	if notBefore.IsZero() {
		return fmt.Errorf("notBefore must be present")
	}
	if notAfter.IsZero() {
		return fmt.Errorf("notAfter must be present")
	}
	cert.x509Cert.NotBefore = notBefore
	cert.x509Cert.NotAfter = notAfter
	return nil
}

func (cert *CertManager) SetSubjectAltNameDNSName(dnsNames []string) error {
	if len(dnsNames) == 0 {
		return fmt.Errorf("DNSName(s) must be provided")
	}
	cert.x509Cert.DNSNames = dnsNames
	return nil
}

func (cert *CertManager) SetSubjectAltNameEmail(emailAddresses []string) error {
	if len(emailAddresses) == 0 {
		return fmt.Errorf("email address(es) must be provided")
	}
	cert.x509Cert.EmailAddresses = emailAddresses
	return nil
}

func (cert *CertManager) SetKeyUsages(keyUsages []string) error {
	if len(keyUsages) == 0 {
		return fmt.Errorf("key usages must be provided")
	}
	var keyUsage x509.KeyUsage
	for _, ku := range keyUsages {
		switch ku {
		case "digitalSignature":
			keyUsage |= x509.KeyUsageDigitalSignature
		case "nonRepudiation":
			keyUsage |= x509.KeyUsageContentCommitment
		case "keyEncipherment":
			keyUsage |= x509.KeyUsageKeyEncipherment
		case "dataEncipherment":
			keyUsage |= x509.KeyUsageDataEncipherment
		case "keyAgreement":
			keyUsage |= x509.KeyUsageKeyAgreement
		case "keyCertSign":
			keyUsage |= x509.KeyUsageCertSign
		case "cRLSign":
			keyUsage |= x509.KeyUsageCRLSign
		case "encipherOnly":
			keyUsage |= x509.KeyUsageEncipherOnly
		case "decipherOnly":
			keyUsage |= x509.KeyUsageDecipherOnly
		default:
			return fmt.Errorf("invalid key usage value")
		}
	}
	cert.x509Cert.KeyUsage = keyUsage
	return nil
}

func (cert *CertManager) SetExtendedKeyUsages(extkeyUsages []string, critical bool) error {
	if len(extkeyUsages) == 0 {
		return fmt.Errorf("extended key usages must be provided")
	}
	var extkeyUsagesOIDs []asn1.ObjectIdentifier
	for _, eku := range extkeyUsages {
		ekuOID, ok := extendedKeyUsages[eku]
		if ok {
			extkeyUsagesOIDs = append(extkeyUsagesOIDs, ekuOID)
		} else { // must be custom OID
			asn1ObjID, err := util.ConvertStringOIDToASN1OID(eku)
			if err != nil {
				return fmt.Errorf("unable to convert string OID to asn1.ObjectIdentifier: %w", err)
			}
			extkeyUsagesOIDs = append(extkeyUsagesOIDs, asn1ObjID)
		}
	}
	extKeyUsageDER, err := asn1.Marshal(extkeyUsagesOIDs)
	if err != nil {
		return fmt.Errorf("unable to marshal extended key usage OIDs: %w", err)
	}
	cert.x509Cert.ExtraExtensions = append(cert.x509Cert.ExtraExtensions, pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 37},
		Value:    extKeyUsageDER,
		Critical: critical,
	})
	return nil
}

func (cert *CertManager) SetAKI(publicKey crypto.PublicKey) error {
	if publicKey == nil {
		return fmt.Errorf("public key for AKI must be provided")
	}
	keyIdentifier, err := util.GenerateSHA1KeyID(publicKey)
	if err != nil {
		return fmt.Errorf("unable to generate SHA1 AKI: %w", err)
	}
	cert.x509Cert.AuthorityKeyId = keyIdentifier
	return nil
}

func (cert *CertManager) SetSKI(publicKey crypto.PublicKey) error {
	if publicKey == nil {
		return fmt.Errorf("public key for SKI must be provided")
	}
	keyIdentifier, err := util.GenerateSHA1KeyID(publicKey)
	if err != nil {
		return fmt.Errorf("unable to generate SHA1 SKI: %w", err)
	}
	cert.x509Cert.SubjectKeyId = keyIdentifier
	return nil
}

func (cert *CertManager) SetCDPs(cdps []string) error {
	if len(cdps) == 0 {
		return fmt.Errorf("CDP(s) must be provided")
	}
	cert.x509Cert.CRLDistributionPoints = cdps
	return nil
}

func (cert *CertManager) SetAIAOCSPs(ocsps []string) error {
	if len(ocsps) == 0 {
		return fmt.Errorf("OCSP responder address(es) must be provided")
	}
	cert.x509Cert.OCSPServer = ocsps
	return nil
}

func (cert *CertManager) SetCertificatePolicies(policyInfos []PolicyInfo, critical bool) error {
	if len(policyInfos) == 0 {
		return fmt.Errorf("policy infos must be provided")
	}
	var policyInformations []policyInformation
	for _, policyInfo := range policyInfos {
		var policyInformation policyInformation
		policyOID, err := util.ConvertStringOIDToASN1OID(policyInfo.PolicyOID)
		if err != nil {
			return fmt.Errorf("unable to convert string policy OID to asn1 object identifier: %w", err)
		}
		policyInformation.PolicyIdentifier = policyOID

		var policyQualifierInfos []policyQualifierInfo
		if len(policyInfo.CpsURI) != 0 {
			policyQualifierInfo := policyQualifierInfo{
				PolicyQualifierId: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1},
				CPSuri:            policyInfo.CpsURI,
			}
			policyQualifierInfos = append(policyQualifierInfos, policyQualifierInfo)
		}
		if len(policyInfo.UserNotice) != 0 {
			policyQualifierInfo := policyQualifierInfo{
				PolicyQualifierId: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 2},
				UserNotice: userNotice{
					ExplicitText: policyInfo.UserNotice,
				},
			}
			policyQualifierInfos = append(policyQualifierInfos, policyQualifierInfo)
		}
		if len(policyQualifierInfos) != 0 {
			policyInformation.PolicyQualifiers = policyQualifierInfos
		}
		policyInformations = append(policyInformations, policyInformation)
	}
	extCertPoliciesDER, err := asn1.Marshal(policyInformations)
	if err != nil {
		return fmt.Errorf("unable to marshal policy informations ASN.1 structure: %w", err)
	}
	cert.x509Cert.ExtraExtensions = append(cert.x509Cert.ExtraExtensions, pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 32},
		Value:    extCertPoliciesDER,
		Critical: critical,
	})
	return nil
}

func (cert *CertManager) SetAIACertIssuers(issuerCertURLs []string) error {
	if len(issuerCertURLs) == 0 {
		return fmt.Errorf("AIA issuer cert URL(s) must be provided")
	}
	cert.x509Cert.IssuingCertificateURL = issuerCertURLs
	return nil
}

func (cert *CertManager) SetBasicConstraints(isCA bool, pathLength int) {
	cert.x509Cert.BasicConstraintsValid = true
	cert.x509Cert.IsCA = isCA
	if isCA {
		if pathLength == 0 {
			cert.x509Cert.MaxPathLen = pathLength
			cert.x509Cert.MaxPathLenZero = true
		} else {
			cert.x509Cert.MaxPathLen = pathLength
		}
	}
}

func (cert *CertManager) SetOCSPNoCheck(critical bool) {
	cert.x509Cert.ExtraExtensions = append(cert.x509Cert.ExtraExtensions, pkix.Extension{
		Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5},
		Value:    asn1.NullRawValue.Bytes,
		Critical: critical,
	})
}

func (cert *CertManager) SetCustomExtension(oid string, value []byte, critical bool) error {
	asn1OID, err := util.ConvertStringOIDToASN1OID(oid)
	if err != nil {
		return fmt.Errorf("unable to convert string custom extenstion OID to asn1 object identifier: %w", err)
	}
	cert.x509Cert.ExtraExtensions = append(cert.x509Cert.ExtraExtensions, pkix.Extension{
		Id:       asn1OID,
		Value:    value,
		Critical: critical,
	})
	return nil
}

func (cert *CertManager) SetIssuerCertificate(issuerCert *x509.Certificate) error {
	if issuerCert == nil {
		return fmt.Errorf("issuer certificate must be provided")
	}
	cert.issuerCert = issuerCert
	return nil
}

func (cert *CertManager) Sign(sigAlgo x509.SignatureAlgorithm, privKey crypto.PrivateKey) (string, error) {
	cert.x509Cert.SignatureAlgorithm = sigAlgo
	if cert.issuerCert == nil {
		cert.issuerCert = cert.x509Cert
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert.x509Cert, cert.issuerCert, cert.x509Cert.PublicKey, privKey)
	if err != nil {
		return "", fmt.Errorf("unable to create X509 certificate: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})), nil
}
