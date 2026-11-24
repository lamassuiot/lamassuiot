package helpers

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
)

// PublicKeyDigest is the name every crypto engine gives a key: the lowercase hex SHA-256 of the DER
// encoding of its SubjectPublicKeyInfo.
func PublicKeyDigest(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}

	digest := sha256.Sum256(der)
	return hex.EncodeToString(digest[:]), nil
}

// StoredPublicKeyDigest is PublicKeyDigest of a public key as the KMS stores it: the base64 of a PEM
// "PUBLIC KEY" block. A value that is not such a key is an error: no digest is invented for it.
func StoredPublicKeyDigest(publicKey string) (string, error) {
	pemBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return "", fmt.Errorf("public key is not base64: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return "", errors.New("public key is not a PEM PUBLIC KEY block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("public key is not a PKIX public key: %w", err)
	}
	return PublicKeyDigest(pub)
}
