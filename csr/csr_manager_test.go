package csr

import (
	"crypto/x509"
	"go-ca/key"
	"go-ca/util"
	"testing"

	"github.com/digitorus/pkcs11"
	"github.com/stretchr/testify/assert"
)

func TestCSRGenerationRSASoftware(t *testing.T) {
	key, err := key.GenerateRSAPrivateKey(2048)
	if err != nil {
		assert.FailNowf(t, "failed to generate RSA-2048 private key - %s", err.Error())
	}
	SubjectInfo := util.SubjectInfo{
		CommonName:         "test.com",
		Organization:       "ACME Corp",
		OrganizationalUnit: "Development",
		Country:            "PK",
	}
	CSRManager, err := CreateCSR(&SubjectInfo, key.GetRSAPublicKey())
	if err != nil {
		assert.FailNow(t, err.Error())
	}
	CSRManager.AddDNSNames([]string{"check.com, abc.com"})
	CSRPEM, err := CSRManager.Sign(x509.SHA256WithRSA, key.GetRSAPrivateKey())
	if err != nil {
		assert.FailNow(t, err.Error())
	}
	CSRManager, err = ParseCSR(CSRPEM)
	if err != nil {
		assert.FailNow(t, err.Error())
	}
	subject, err := CSRManager.GetSubject()
	if err != nil {
		assert.FailNow(t, err.Error())
	}
	assert.Equal(t, "test.com", subject.CommonName, "CommonName should be test.com")
	assert.Equal(t, "ACME Corp", subject.Organization, "Organization should be ACME Corp")
	assert.Equal(t, "Development", subject.OrganizationalUnit, "OrganizationalUnit should be Development")
	assert.Equal(t, "PK", subject.Country, "Country should be PK")
	assert.EqualValues(t, []string{"check.com, abc.com"}, CSRManager.GetDNSNames())
	assert.Nil(t, CSRManager.VerifySignature(), "CSR signature verification failed")
}

func TestCSRGenerationECSoftware(t *testing.T) {
	key, err := key.GenerateECDSAPrivateKey("secp256r1")
	if err != nil {
		assert.FailNow(t, "failed to generate ECDSA private key having curve p-384 - %s", err.Error())
	}
	SubjectInfo := util.SubjectInfo{
		CommonName:             "Bilal Ashraf",
		GivenName:              "Bilal",
		Surname:                "Ashraf",
		Organization:           "ACME Corp",
		OrganizationalUnit:     "Development",
		OrganizationIdentifier: "ORG-123-456",
		Country:                "PK",
	}
	CSRManager, err := CreateCSR(&SubjectInfo, key.GetECDSAPublicKey())
	if err != nil {
		assert.FailNow(t, err.Error())
	}
	CSRPEM, err := CSRManager.Sign(x509.ECDSAWithSHA256, key.GetECDSAPrivateKey())
	if err != nil {
		assert.FailNow(t, err.Error())
	}
	CSRManager, err = ParseCSR(CSRPEM)
	if err != nil {
		assert.FailNow(t, err.Error())
	}
	subject, err := CSRManager.GetSubject()
	if err != nil {
		assert.FailNow(t, err.Error())
	}
	assert.Equal(t, "Bilal Ashraf", subject.CommonName, "CommonName should be Bilal Ashraf")
	assert.Equal(t, "Bilal", subject.GivenName, "GivenName should be Bilal")
	assert.Equal(t, "Ashraf", subject.Surname, "Surname should be Ashraf")
	assert.Equal(t, "ACME Corp", subject.Organization, "Organization should be ACME Corp")
	assert.Equal(t, "Development", subject.OrganizationalUnit, "OrganizationalUnit should be Development")
	assert.Equal(t, "ORG-123-456", subject.OrganizationIdentifier, "OrganizationIdentifier should be ORG-123-456")
	assert.Equal(t, "PK", subject.Country, "Country should be PK")
	assert.Nil(t, CSRManager.VerifySignature(), "CSR signature verification failed")
}

func TestCSRGenerationRSAHardware(t *testing.T) {
	context := pkcs11.New("/usr/lib/softhsm/libsofthsm2.so")
	if context == nil {
		assert.FailNow(t, "unable to load PKCS#11 context")
	}
	defer context.Destroy()
	defer context.Finalize()

	err := context.Initialize()
	if err != nil {
		assert.FailNow(t, err.Error())
	}
	session, err := pkcs11.CreateSession(context, 934371267, "1234", true)
	if err != nil {
		assert.FailNow(t, err.Error())
	}
	err = key.GenerateHardwareKeyPair(context, session, &key.KeyAlgo{
		KeyAlgo:   "RSA",
		KeyLength: 2048,
	}, "RSA-2048")
	if err != nil {
		assert.FailNow(t, err.Error())
	}
	privKey, err := pkcs11.InitPrivateKey(context, session, []byte("RSA-2048"))
	if err != nil {
		assert.FailNow(t, err.Error())
	}
	SubjectInfo := util.SubjectInfo{
		CommonName:             "Bilal Ashraf",
		GivenName:              "Bilal",
		Surname:                "Ashraf",
		Organization:           "ACME Corp",
		OrganizationalUnit:     "Development",
		OrganizationIdentifier: "ORG-123-456",
		Country:                "PK",
	}
	CSRManager, err := CreateCSR(&SubjectInfo, privKey.Public())
	if err != nil {
		assert.FailNow(t, err.Error())
	}
	CSRPEM, err := CSRManager.Sign(x509.SHA256WithRSA, privKey)
	if err != nil {
		assert.FailNow(t, err.Error())
	}
	CSRManager, err = ParseCSR(CSRPEM)
	if err != nil {
		assert.FailNow(t, err.Error())
	}
	subject, err := CSRManager.GetSubject()
	if err != nil {
		assert.FailNow(t, err.Error())
	}
	assert.Equal(t, "Bilal Ashraf", subject.CommonName, "CommonName should be Bilal Ashraf")
	assert.Equal(t, "Bilal", subject.GivenName, "GivenName should be Bilal")
	assert.Equal(t, "Ashraf", subject.Surname, "Surname should be Ashraf")
	assert.Equal(t, "ACME Corp", subject.Organization, "Organization should be ACME Corp")
	assert.Equal(t, "Development", subject.OrganizationalUnit, "OrganizationalUnit should be Development")
	assert.Equal(t, "ORG-123-456", subject.OrganizationIdentifier, "OrganizationIdentifier should be ORG-123-456")
	assert.Equal(t, "PK", subject.Country, "Country should be PK")
	assert.Nil(t, CSRManager.VerifySignature(), "CSR signature verification failed")

	err = key.DeleteHardwareKeyPair(context, session, "RSA-2048")
	if err != nil {
		assert.FailNow(t, err.Error())
	}
}

func TestCSRGenerationECHardware(t *testing.T) {
	context := pkcs11.New("/usr/lib/softhsm/libsofthsm2.so")
	if context == nil {
		assert.FailNow(t, "unable to load PKCS#11 context")
	}
	defer context.Destroy()
	defer context.Finalize()

	err := context.Initialize()
	if err != nil {
		assert.FailNow(t, err.Error())
	}
	session, err := pkcs11.CreateSession(context, 934371267, "1234", true)
	if err != nil {
		assert.FailNow(t, err.Error())
	}
	err = key.GenerateHardwareKeyPair(context, session, &key.KeyAlgo{
		KeyAlgo: "ECDSA",
		Curve:   "secp256r1",
	}, "ECDSA-P256")
	if err != nil {
		assert.FailNow(t, err.Error())
	}
	privKey, err := pkcs11.InitPrivateKey(context, session, []byte("ECDSA-P256"))
	if err != nil {
		assert.FailNow(t, err.Error())
	}
	SubjectInfo := util.SubjectInfo{
		CommonName:             "Bilal Ashraf",
		GivenName:              "Bilal",
		Surname:                "Ashraf",
		Organization:           "ACME Corp",
		OrganizationalUnit:     "Development",
		OrganizationIdentifier: "ORG-123-456",
		Country:                "PK",
	}
	CSRManager, err := CreateCSR(&SubjectInfo, privKey.Public())
	if err != nil {
		assert.FailNow(t, err.Error())
	}
	CSRPEM, err := CSRManager.Sign(x509.ECDSAWithSHA256, privKey)
	if err != nil {
		assert.FailNow(t, err.Error())
	}
	CSRManager, err = ParseCSR(CSRPEM)
	if err != nil {
		assert.FailNow(t, err.Error())
	}
	subject, err := CSRManager.GetSubject()
	if err != nil {
		assert.FailNow(t, err.Error())
	}
	assert.Equal(t, "Bilal Ashraf", subject.CommonName, "CommonName should be Bilal Ashraf")
	assert.Equal(t, "Bilal", subject.GivenName, "GivenName should be Bilal")
	assert.Equal(t, "Ashraf", subject.Surname, "Surname should be Ashraf")
	assert.Equal(t, "ACME Corp", subject.Organization, "Organization should be ACME Corp")
	assert.Equal(t, "Development", subject.OrganizationalUnit, "OrganizationalUnit should be Development")
	assert.Equal(t, "ORG-123-456", subject.OrganizationIdentifier, "OrganizationIdentifier should be ORG-123-456")
	assert.Equal(t, "PK", subject.Country, "Country should be PK")
	assert.Nil(t, CSRManager.VerifySignature(), "CSR signature verification failed")

	err = key.DeleteHardwareKeyPair(context, session, "ECDSA-P256")
	if err != nil {
		assert.FailNow(t, err.Error())
	}
}
