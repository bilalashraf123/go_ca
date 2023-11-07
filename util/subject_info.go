package util

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

type SubjectInfo struct {
	CommonName             string
	GivenName              string
	Surname                string
	Organization           string
	OrganizationalUnit     string
	OrganizationIdentifier string
	Country                string
	Locality               string
	SerialNumber           string
	StateOrProvince        string
	StreetAddress          string
	PostalCode             string
}

var (
	CommonNameOID             = asn1.ObjectIdentifier{2, 5, 4, 3}
	GivenNameOID              = asn1.ObjectIdentifier{2, 5, 4, 42}
	SurnameOID                = asn1.ObjectIdentifier{2, 5, 4, 4}
	OrganizationOID           = asn1.ObjectIdentifier{2, 5, 4, 10}
	OrganizationalUnitOID     = asn1.ObjectIdentifier{2, 5, 4, 11}
	OrganizationIdentifierOID = asn1.ObjectIdentifier{2, 5, 4, 97}
	CountryOID                = asn1.ObjectIdentifier{2, 5, 4, 6}
	LocalityOID               = asn1.ObjectIdentifier{2, 5, 4, 7}
	SerialNumberOID           = asn1.ObjectIdentifier{2, 5, 4, 5}
	StateOrProvinceOID        = asn1.ObjectIdentifier{2, 5, 4, 8}
	StreetAddressOID          = asn1.ObjectIdentifier{2, 5, 4, 9}
	PostalCodeOID             = asn1.ObjectIdentifier{2, 5, 4, 17}
)

func CreateSubject(subject *SubjectInfo) (pkix.Name, error) {
	if subject == nil {
		return pkix.Name{}, fmt.Errorf("subject name must be provided")
	}
	var name pkix.Name
	if len(subject.Country) != 0 {
		name.Country = []string{subject.Country}
	}
	if len(subject.Organization) != 0 {
		name.Organization = []string{subject.Organization}
	}
	if len(subject.OrganizationalUnit) != 0 {
		name.OrganizationalUnit = []string{subject.OrganizationalUnit}
	}
	if len(subject.Locality) != 0 {
		name.Locality = []string{subject.Locality}
	}
	if len(subject.StateOrProvince) != 0 {
		name.Province = []string{subject.StateOrProvince}
	}
	if len(subject.StreetAddress) != 0 {
		name.StreetAddress = []string{subject.StreetAddress}
	}
	if len(subject.PostalCode) != 0 {
		name.PostalCode = []string{subject.PostalCode}
	}
	if len(subject.SerialNumber) != 0 {
		name.SerialNumber = subject.SerialNumber
	}
	if len(subject.CommonName) != 0 {
		name.CommonName = subject.CommonName
	}

	var names []pkix.AttributeTypeAndValue
	if len(subject.GivenName) != 0 {
		givenName := pkix.AttributeTypeAndValue{
			Type:  asn1.ObjectIdentifier{2, 5, 4, 42},
			Value: subject.GivenName,
		}
		names = append(names, givenName)
	}
	if len(subject.Surname) != 0 {
		surname := pkix.AttributeTypeAndValue{
			Type:  asn1.ObjectIdentifier{2, 5, 4, 4},
			Value: subject.Surname,
		}
		names = append(names, surname)
	}
	if len(subject.OrganizationIdentifier) != 0 {
		orgIdentifier := pkix.AttributeTypeAndValue{
			Type:  asn1.ObjectIdentifier{2, 5, 4, 97},
			Value: subject.OrganizationIdentifier,
		}
		names = append(names, orgIdentifier)
	}
	if len(names) != 0 {
		name.ExtraNames = names
	}
	return name, nil
}

func CreateSubjectInfo(subjectName pkix.Name) (*SubjectInfo, error) {
	var subject SubjectInfo

	names := subjectName.Names
	for _, attrTypeValue := range names {
		if attrTypeValue.Type.Equal(CommonNameOID) {
			subject.CommonName = attrTypeValue.Value.(string)
		}
		if attrTypeValue.Type.Equal(GivenNameOID) {
			subject.GivenName = attrTypeValue.Value.(string)
		}
		if attrTypeValue.Type.Equal(SurnameOID) {
			subject.Surname = attrTypeValue.Value.(string)
		}
		if attrTypeValue.Type.Equal(OrganizationOID) {
			subject.Organization = attrTypeValue.Value.(string)
		}
		if attrTypeValue.Type.Equal(OrganizationalUnitOID) {
			subject.OrganizationalUnit = attrTypeValue.Value.(string)
		}
		if attrTypeValue.Type.Equal(OrganizationIdentifierOID) {
			subject.OrganizationIdentifier = attrTypeValue.Value.(string)
		}
		if attrTypeValue.Type.Equal(CountryOID) {
			subject.Country = attrTypeValue.Value.(string)
		}
		if attrTypeValue.Type.Equal(LocalityOID) {
			subject.Locality = attrTypeValue.Value.(string)
		}
		if attrTypeValue.Type.Equal(SerialNumberOID) {
			subject.SerialNumber = attrTypeValue.Value.(string)
		}
		if attrTypeValue.Type.Equal(StateOrProvinceOID) {
			subject.StateOrProvince = attrTypeValue.Value.(string)
		}
		if attrTypeValue.Type.Equal(StreetAddressOID) {
			subject.StreetAddress = attrTypeValue.Value.(string)
		}
		if attrTypeValue.Type.Equal(PostalCodeOID) {
			subject.PostalCode = attrTypeValue.Value.(string)
		}
	}
	return &subject, nil
}
