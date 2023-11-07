package key

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

type ecdsaKeyManager struct {
	privateKey *ecdsa.PrivateKey
}

func GenerateECDSAPrivateKey(curve string) (*ecdsaKeyManager, error) {
	var keyCurve elliptic.Curve

	switch curve {
	case "secp256r1":
		keyCurve = elliptic.P256()
	case "secp384r1":
		keyCurve = elliptic.P384()
	case "secp521r1":
		keyCurve = elliptic.P521()
	default:
		return nil, fmt.Errorf("curve value must be either secp256r1, secp384r1 or secp521r1")
	}
	reader := rand.Reader
	privateKey, err := ecdsa.GenerateKey(keyCurve, reader)
	if err != nil {
		return nil, fmt.Errorf("unable to generate ECDSA key pair with curve %s: %w", curve, err)
	}
	return &ecdsaKeyManager{privateKey: privateKey}, nil
}

func (key *ecdsaKeyManager) GetECDSAPrivateKeyPEM() (string, error) {
	privateKeyBytes, err := x509.MarshalECPrivateKey(key.privateKey)
	if err != nil {
		return "", fmt.Errorf("unable to marshal ECDSA private key: %w", err)
	}
	privateKeyPEMBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: privateKeyBytes,
		},
	)
	return string(privateKeyPEMBytes), nil
}

func (key *ecdsaKeyManager) GetECDSAPrivateKey() crypto.PrivateKey {
	return key.privateKey
}

func (key *ecdsaKeyManager) GetECDSAPrivateKeyDER() ([]byte, error) {
	privateKeyBytes, err := x509.MarshalECPrivateKey(key.privateKey)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal ECDSA private key: %w", err)
	}
	return privateKeyBytes, nil
}

func (key *ecdsaKeyManager) GetECDSAPublicKey() crypto.PublicKey {
	return key.privateKey.Public()
}

func (key *ecdsaKeyManager) GetECDSAPublicKeyPEM() (string, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(key.privateKey.Public())
	if err != nil {
		return "", fmt.Errorf("unable to marshal ECDSA public key: %w", err)
	}
	publicKeyPEMBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKeyBytes,
		},
	)
	return string(publicKeyPEMBytes), nil
}

func (key *ecdsaKeyManager) GetECDSAPublicKeyDER() ([]byte, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(key.privateKey.Public())
	if err != nil {
		return nil, fmt.Errorf("unable to marshal ECDSA public key: %w", err)
	}
	return pubKeyBytes, nil
}
