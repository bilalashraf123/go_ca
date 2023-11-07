package csr

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"go-ca/util"
)

type CSRManager struct {
	certRequest x509.CertificateRequest
}

func CreateCSR(subject *util.SubjectInfo, publicKey crypto.PublicKey) (*CSRManager, error) {
	name, err := util.CreateSubject(subject)
	if err != nil {
		return nil, fmt.Errorf("unable to create pkix name from subject information: %w", err)
	}
	return &CSRManager{
		certRequest: x509.CertificateRequest{
			Subject:   name,
			PublicKey: publicKey,
		},
	}, nil
}

func (csr *CSRManager) AddDNSNames(dnsName []string) error {
	if len(dnsName) == 0 {
		return fmt.Errorf("DNS name must be provided")
	}
	csr.certRequest.DNSNames = dnsName
	return nil
}

func (csr *CSRManager) AddEmailAddresses(emailAddresses []string) error {
	if len(emailAddresses) == 0 {
		return fmt.Errorf("email addresses name must be provided")
	}
	csr.certRequest.EmailAddresses = emailAddresses
	return nil
}

func (csr *CSRManager) Sign(sigAlgo x509.SignatureAlgorithm, privKey crypto.PrivateKey) (string, error) {
	csr.certRequest.SignatureAlgorithm = sigAlgo
	csrDerBytes, err := x509.CreateCertificateRequest(rand.Reader, &csr.certRequest, privKey)
	if err != nil {
		return "", fmt.Errorf("unable to create CSR: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDerBytes,
	})), nil
}

func ParseCSR(pemCsr string) (*CSRManager, error) {
	block, _ := pem.Decode([]byte(pemCsr))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate request")
	}
	certRequest, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse CSR: %w", err)
	}
	return &CSRManager{
		certRequest: *certRequest,
	}, nil
}

func (csr *CSRManager) GetSubject() (*util.SubjectInfo, error) {
	subjectInfo, err := util.CreateSubjectInfo(csr.certRequest.Subject)
	if err != nil {
		return nil, fmt.Errorf("unable to create subject information from pkix name: %w", err)
	}
	return subjectInfo, nil
}

func (csr *CSRManager) GetPublicKey() crypto.PublicKey {
	return csr.certRequest.PublicKey
}

func (csr *CSRManager) VerifySignature() error {
	return csr.certRequest.CheckSignature()
}

func (csr *CSRManager) GetDNSNames() []string {
	return csr.certRequest.DNSNames
}

func (csr *CSRManager) GetEmailAddresses() []string {
	return csr.certRequest.EmailAddresses
}
