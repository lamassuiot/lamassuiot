package cms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
)

// Technique is the CMS key-management technique used to deliver the content-
// encryption key (CEK) to the recipient. It is normally derived from the
// recipient credential's key type via TechniqueFor, not chosen by hand.
type Technique int

const (
	// TechniqueKeyTransport is ktri / RSA key transport (RFC 5652 §6.2.1): the
	// CEK is RSA-OAEP-encrypted directly to the recipient's RSA public key.
	TechniqueKeyTransport Technique = iota
	// TechniqueKeyAgreement is kari / ECDH key agreement (RFC 5652 §6.2.2): a
	// shared secret is derived against the recipient's EC public key, run
	// through the ANSI-X9.63 KDF, and used to AES-key-wrap the CEK.
	TechniqueKeyAgreement
)

func (t Technique) String() string {
	switch t {
	case TechniqueKeyTransport:
		return "ktri"
	case TechniqueKeyAgreement:
		return "kari"
	default:
		return "unknown"
	}
}

// TechniqueFor selects the CMS key-management technique from a recipient public
// key: RSA → key transport (ktri), ECDSA → key agreement (kari). It returns an
// error for unsupported key types.
func TechniqueFor(pub crypto.PublicKey) (Technique, error) {
	switch pub.(type) {
	case *rsa.PublicKey:
		return TechniqueKeyTransport, nil
	case *ecdsa.PublicKey:
		return TechniqueKeyAgreement, nil
	default:
		return 0, fmt.Errorf("cms: unsupported recipient key type %T (only RSA and ECDSA are supported)", pub)
	}
}
