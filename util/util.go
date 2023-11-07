package util

import (
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strconv"
	"strings"
)

func ConvertStringOIDToASN1OID(objectIdentifier string) (asn1.ObjectIdentifier, error) {
	var asn1OID []int

	OIDStrArray := strings.Split(objectIdentifier, ".")
	for _, OIDPart := range OIDStrArray {
		OIDPartInt, err := strconv.Atoi(OIDPart)
		if err != nil {
			return nil, fmt.Errorf("unable to convert atoi: %w", err)
		}
		asn1OID = append(asn1OID, OIDPartInt)
	}
	return asn1OID, nil
}

func GenerateSHA1KeyID(publicKey crypto.PublicKey) ([]byte, error) {
	pkixPubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal public key: %w", err)
	}
	var pkixPublicKey struct {
		Algo      pkix.AlgorithmIdentifier
		BitString asn1.BitString
	}
	_, err = asn1.Unmarshal(pkixPubKeyBytes, &pkixPublicKey)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal public key: %w", err)
	}
	kid := sha1.Sum(pkixPublicKey.BitString.Bytes)
	return kid[:], nil
}
