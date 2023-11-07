package cert

import "encoding/asn1"

type PolicyInfo struct {
	PolicyOID  string
	CpsURI     string
	UserNotice string
}

type policyInformation struct {
	PolicyIdentifier asn1.ObjectIdentifier
	PolicyQualifiers []policyQualifierInfo `asn1:"optional"`
}

type policyQualifierInfo struct {
	PolicyQualifierId asn1.ObjectIdentifier
	CPSuri            string     `asn1:"optional,ia5"`
	UserNotice        userNotice `asn1:"optional"`
}

type userNotice struct {
	NoticeRef    noticeReference `asn1:"optional"`
	ExplicitText string          `asn1:"optional,utf8"`
}

type noticeReference struct {
	Organization  string `asn1:"utf8"`
	NoticeNumbers []int
}
