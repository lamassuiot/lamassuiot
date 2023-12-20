package models

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

type PrivateKey struct {
	any
}

func (pk PrivateKey) GetPublicKeyAlgorithm() (x509.PublicKeyAlgorithm, error) {
	switch t := pk.any.(type) {
	case (rsa.PrivateKey):
		return x509.RSA, nil
	case (ecdsa.PrivateKey):
		return x509.ECDSA, nil
	default:
		return -1, fmt.Errorf("private key can not be of type %s", t)
	}
}

func (pk PrivateKey) BytesToKey(keyBytes []byte) error {
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return fmt.Errorf("failed to parse PEM block containing the key")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return err
		}

		pk.any = key
		return nil
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return err
		}

		pk.any = key
		return nil

	default:
		return fmt.Errorf("unsupported key type")
	}

}
