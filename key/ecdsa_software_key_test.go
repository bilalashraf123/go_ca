package key

import (
	"testing"
)

func TestGenerateKeysECDSA(t *testing.T) {
	curves := []string{
		"secp256r1", "secp384r1", "secp521r1",
	}
	for _, curve := range curves {
		_, err := GenerateECDSAPrivateKey(curve)
		if err != nil {
			t.Errorf("failed to generate ECDSA private key having curve %s - %s", curve, err.Error())
		}
	}
}

func TestGetECDSAPrivateKeyPEM(t *testing.T) {
	key, err := GenerateECDSAPrivateKey("secp256r1")
	if err != nil {
		t.Errorf("failed to generate ECDSA private key having curve secp256r1 - %s", err.Error())
	}
	key.GetECDSAPrivateKeyPEM()
}

func TestGetECDSAPrivateKeyDER(t *testing.T) {
	key, err := GenerateECDSAPrivateKey("secp384r1")
	if err != nil {
		t.Errorf("failed to generate ECDSA private key having curve secp384r1 - %s", err.Error())
	}
	key.GetECDSAPrivateKeyDER()
}

func TestGetECDSAPublicKey(t *testing.T) {
	key, err := GenerateECDSAPrivateKey("secp256r1")
	if err != nil {
		t.Errorf("failed to generate ECDSA private key having curve secp256r1 - %s", err.Error())
	}
	key.GetECDSAPublicKey()
}

func TestGetECDSAPublicKeyPEM(t *testing.T) {
	key, err := GenerateECDSAPrivateKey("secp384r1")
	if err != nil {
		t.Errorf("failed to generate ECDSA private key having curve secp384r1 - %s", err.Error())
	}
	key.GetECDSAPublicKeyPEM()
}

func TestGetECDSAPublicKeyDER(t *testing.T) {
	key, err := GenerateECDSAPrivateKey("secp521r1")
	if err != nil {
		t.Errorf("failed to generate ECDSA private key having curve secp521r1 - %s", err.Error())
	}
	key.GetECDSAPublicKeyDER()
}
