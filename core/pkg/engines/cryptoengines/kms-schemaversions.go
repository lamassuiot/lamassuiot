package cryptoengines

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
)

// v1: plain serial number. Example: 11-22-33-44-55-66-77
// v2: hex encoded SHA256 of the public key, a string of 64 characters. Example: 258abc860d364eb39561d69cdaec40164fd54dbad47c8a887112ba19f903757c
// v3: lrn:keyid:v3:<hex encoded SHA256 of the public key, a string of 64 characters>. Example: lrn:keyid:v3:258abc860d364eb39561d69cdaec40164fd54dbad47c8a887112ba19f903757c
type KeyID string

// Should always return a valid key id using the latest SchemaVersion
func GetKeyLRN(key any) (KeyID, error) {
	var pubkeyBytes []byte
	var err error

	pubkeyBytes, err = x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", fmt.Errorf("could not marshal public key: %s", err)
	}

	hash := sha256.New()
	hash.Write(pubkeyBytes)
	digest := hash.Sum(nil)
	// p.logger.Tracef("public key digest (bytes): %x", digest)

	hexDigest := hex.EncodeToString(digest)
	// p.logger.Debugf("public key digest (hex encoded bytes): %s", hexDigest)

	lrn := fmt.Sprintf("lrn:keyid:v3:%s", hexDigest)
	return KeyID(lrn), nil
}

func (k KeyID) GetBaseID() string {
	// Remove the prefix "lrn:keyid:v3:"
	if len(k) > 14 {
		return string(k[14:])
	}

	return ""
}
