package key

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

type rsaKeyManager struct {
	privateKey *rsa.PrivateKey
}

func GenerateRSAPrivateKey(keySize int) (*rsaKeyManager, error) {
	if keySize != 2048 && keySize != 3072 && keySize != 4096 {
		return nil, fmt.Errorf("RSA key size must be either 2048, 3072 or 4096")
	}
	reader := rand.Reader
	privateKey, err := rsa.GenerateKey(reader, keySize)
	if err != nil {
		return nil, fmt.Errorf("unable to generate RSA software key pair: %w", err)
	}
	return &rsaKeyManager{privateKey: privateKey}, nil
}

func (key *rsaKeyManager) GetRSAPrivateKey() crypto.PrivateKey {
	return key.privateKey
}

func (key *rsaKeyManager) GetRSAPrivateKeyPEM() string {
	privateKeyPEMBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key.privateKey),
		},
	)
	return string(privateKeyPEMBytes)
}

func (key *rsaKeyManager) GetRSAPrivateKeyDER() []byte {
	return x509.MarshalPKCS1PrivateKey(key.privateKey)
}

func (key *rsaKeyManager) GetRSAPublicKey() crypto.PublicKey {
	return key.privateKey.Public()
}

func (key *rsaKeyManager) GetRSAPublicKeyPEM() (string, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(key.privateKey.Public())
	if err != nil {
		return "", fmt.Errorf("unable to marshal public key: %w", err)
	}
	publicKeyPEMBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKeyBytes,
		},
	)
	return string(publicKeyPEMBytes), nil
}

func (key *rsaKeyManager) GetRSAPublicKeyDER() ([]byte, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(key.privateKey.Public())
	if err != nil {
		return nil, fmt.Errorf("unable to marshal public key: %w", err)
	}
	return pubKeyBytes, nil
}
