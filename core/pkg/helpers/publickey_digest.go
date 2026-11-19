package helpers

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
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
