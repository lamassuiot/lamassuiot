package helpers

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"regexp"
)

func PublicKeyToPEM(pub any) (string, error) {
	if pub != nil {
		pubBytes, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return "", err
		}

		publicKeyPEM := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubBytes,
		}

		return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(publicKeyPEM)), nil
	} else {
		return "", fmt.Errorf("empty key")
	}
}

func PublicKeyPEMToCryptoKey(pub string) (any, error) {
	//check if is b64 enc. Decode if so
	rx := regexp.MustCompile("^(?:[A-Za-z0-9+\\/]{4})*(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=|[A-Za-z0-9+\\/]{4})$")
	if rx.MatchString(pub) {
		pubB, err := base64.StdEncoding.DecodeString(pub)
		if err != nil {
			return nil, err
		}

		pub = string(pubB)
	}

	keyBlock, _ := pem.Decode([]byte(pub))
	if keyBlock != nil {
		pubKey, err := x509.ParsePKIXPublicKey(keyBlock.Bytes)
		if err != nil {
			return nil, err
		}

		return pubKey, nil
	}

	return nil, fmt.Errorf("missing pubkey block")
}
