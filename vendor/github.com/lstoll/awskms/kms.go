package awskms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

func parsePublicKey(publicKey []byte) (crypto.PublicKey, error) {
	pubk, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	switch pubk.(type) {
	case *rsa.PublicKey:
		return pubk, nil
	case *ecdsa.PublicKey:
		return pubk, nil
	default:
		return nil, fmt.Errorf("public key is of unhandled type: %T", pubk)
	}
}
