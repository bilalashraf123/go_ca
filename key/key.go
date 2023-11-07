package key

import (
	"crypto"
	"fmt"
	"math/big"

	"github.com/digitorus/pkcs11"
	mp11 "github.com/miekg/pkcs11"
)

type KeyAlgo struct {
	KeyAlgo   string
	KeyLength int
	Curve     string
}

func GenerateSoftwareKeyPair(keyAlgo *KeyAlgo) (crypto.PrivateKey, []byte, []byte, error) {
	var privateKey []byte
	var publicKey []byte

	switch keyAlgo.KeyAlgo {
	case "RSA":
		rsaKey, err := GenerateRSAPrivateKey(keyAlgo.KeyLength)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("unable to generate RSA key pair: %w", err)
		}
		privateKey = []byte(rsaKey.GetRSAPrivateKeyPEM())
		publicKeyPEM, err := rsaKey.GetRSAPublicKeyPEM()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("unable to get RSA public key in PEM format: %w", err)
		}
		publicKey = []byte(publicKeyPEM)
		return rsaKey.GetRSAPrivateKey(), privateKey, publicKey, nil
	case "ECDSA":
		ecdsaKey, err := GenerateECDSAPrivateKey(keyAlgo.Curve)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("unable to generate ECDSA key pair: %w", err)
		}
		privateKeyPEM, err := ecdsaKey.GetECDSAPrivateKeyPEM()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("unable to get ECDSA private key in PEM format: %w", err)
		}
		privateKey = []byte(privateKeyPEM)

		publicKeyPEM, err := ecdsaKey.GetECDSAPublicKeyPEM()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("unable to get ECDSA public key in PEM format: %w", err)
		}
		publicKey = []byte(publicKeyPEM)
		return ecdsaKey.GetECDSAPrivateKey(), privateKey, publicKey, nil
	default:
		return nil, nil, nil, fmt.Errorf("invalid key type")
	}
}

func GenerateHardwareKeyPair(context *mp11.Ctx, session mp11.SessionHandle, keyAlgo *KeyAlgo, keyID string) error {
	privKeyObjects, err := pkcs11.GetObjects(context, session, mp11.CKO_PRIVATE_KEY, []byte(keyID), 1)
	if err != nil {
		return fmt.Errorf("unable to get private key handle: %w", err)
	}
	if len(privKeyObjects) != 0 {
		return fmt.Errorf("key pair with ID already exists: %s", keyID)
	}
	pubKeyTemplate := pkcs11.PublicKeyTemplate{
		Token:   true,
		Encrypt: true,
		Verify:  true,
		Wrap:    true,
	}
	p11Key := pkcs11.Key{
		Label: keyID,
		CKAID: keyID,
		Private: pkcs11.PrivateKeyTemplate{
			Token:       true,
			Private:     true,
			Sensitive:   true,
			Extractable: true,
			Decrypt:     true,
			Sign:        true,
			Unwrap:      true,
		},
	}
	switch keyAlgo.KeyAlgo {
	case "RSA":
		if keyAlgo.KeyLength != 2048 && keyAlgo.KeyLength != 3072 && keyAlgo.KeyLength != 4096 {
			return fmt.Errorf("RSA key size must be either 2048, 3072 or 4096")
		}
		p11Key.Type = "RSA"
		pubKeyTemplate.ModulesBits = keyAlgo.KeyLength
		pubKeyTemplate.Exponent = big.NewInt(65537)
	case "ECDSA":
		if keyAlgo.Curve != "secp256r1" && keyAlgo.Curve != "secp384r1" && keyAlgo.Curve != "secp521r1" {
			return fmt.Errorf("curve value must be either secp256r1, secp384r1 or secp521r1")
		}
		p11Key.Type = "ECDSA"
		pubKeyTemplate.Curve = keyAlgo.Curve
	default:
		return fmt.Errorf("invalid key algorithm: %s", keyAlgo.KeyAlgo)
	}
	p11Key.Public = pubKeyTemplate
	_, _, err = pkcs11.CreateKey(context, session, p11Key)
	if err != nil {
		return fmt.Errorf("unable to generate key pair: %w", err)
	}
	return nil
}

func DeleteHardwareKeyPair(context *mp11.Ctx, session mp11.SessionHandle, keyID string) error {
	privKeyObjects, err := pkcs11.GetObjects(context, session, mp11.CKO_PRIVATE_KEY, []byte(keyID), 1)
	if err != nil {
		return fmt.Errorf("unable to get private key handle: %w", err)
	}
	if len(privKeyObjects) == 0 {
		return fmt.Errorf("private key with ID does not exist: %s", keyID)
	}
	err = context.DestroyObject(session, privKeyObjects[0].Id)
	if err != nil {
		return fmt.Errorf("unable to delete private key object: %w", err)
	}
	pubKeyObjects, err := pkcs11.GetObjects(context, session, mp11.CKO_PUBLIC_KEY, []byte(keyID), 1)
	if err != nil {
		return fmt.Errorf("unable to get public key handle: %w", err)
	}
	if len(pubKeyObjects) == 0 {
		return fmt.Errorf("public key with ID does not exist: %s", keyID)
	}
	err = context.DestroyObject(session, pubKeyObjects[0].Id)
	if err != nil {
		return fmt.Errorf("unable to delete public key object: %w", err)
	}
	return nil
}
