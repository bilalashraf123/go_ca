package key

import (
	"testing"
)

func TestGenerateKeysRSA(t *testing.T) {
	keySizes := []int{
		2048, 3072, 4096,
	}
	for _, keySize := range keySizes {
		_, err := GenerateRSAPrivateKey(2048)
		if err != nil {
			t.Errorf("failed to generate RSA-%d private key - %s", keySize, err.Error())
		}
	}
}

func TestGetRSAPrivateKeyPEM(t *testing.T) {
	key, err := GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Errorf("failed to generate RSA-2048 private key - %s", err.Error())
	}
	key.GetRSAPrivateKeyPEM()
}

func TestGetRSAPrivateKeyDER(t *testing.T) {
	key, err := GenerateRSAPrivateKey(3072)
	if err != nil {
		t.Errorf("failed to generate RSA-3072 private key - %s", err.Error())
	}
	key.GetRSAPrivateKeyDER()
}

func TestGetRSAPublicKey(t *testing.T) {
	key, err := GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Errorf("failed to generate RSA-2048 private key - %s", err.Error())
	}
	key.GetRSAPublicKey()
}

func TestGetRSAPublicKeyPEM(t *testing.T) {
	key, err := GenerateRSAPrivateKey(3072)
	if err != nil {
		t.Errorf("failed to generate RSA-3072 private key - %s", err.Error())
	}
	key.GetRSAPublicKeyPEM()
}

func TestGetRSAPublicKeyDER(t *testing.T) {
	key, err := GenerateRSAPrivateKey(4096)
	if err != nil {
		t.Errorf("failed to generate RSA-4096 private key - %s", err.Error())
	}
	key.GetRSAPublicKeyDER()
}
