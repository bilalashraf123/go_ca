package util

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"hash"
	"math/big"
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

func GenerateRandomNumber(noOfBytes int) (*big.Int, error) {
	randBytes := make([]byte, noOfBytes)
	_, err := rand.Read(randBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to generate random bytes for serial number: %w", err)
	}
	serialNumber := new(big.Int)
	serialNumber.SetBytes(randBytes)
	return serialNumber, nil
}

func GetMessageDigest(digestAlgo string, data []byte) (crypto.Hash, []byte, error) {
	var hash hash.Hash
	var crytoHash crypto.Hash
	switch digestAlgo {
	case "sha256":
		hash = sha256.New()
		crytoHash = crypto.SHA256
	case "sha384":
		hash = sha512.New384()
		crytoHash = crypto.SHA384
	case "sha512":
		hash = sha512.New()
		crytoHash = crypto.SHA512
	default:
		return 0, nil, fmt.Errorf("invalid digest algorithm parameter: %s", digestAlgo)
	}
	hash.Write(data)
	return crytoHash, hash.Sum(nil), nil
}
