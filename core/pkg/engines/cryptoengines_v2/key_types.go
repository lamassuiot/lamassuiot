package cryptoenginesv2

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"time"
)

type KeyID string
type AlgorithmID string

type KeyState string

const (
	StateEnabled       KeyState = "enabled"
	StateDisabled      KeyState = "disabled"
	StatePendingDelete KeyState = "pendingDeletion"
	StateDestroyed     KeyState = "destroyed"
)

type KeyOrigin string

const (
	OriginGenerated KeyOrigin = "generated"
	OriginImported  KeyOrigin = "imported"
	OriginExternal  KeyOrigin = "external"
)

type KeyMetadata struct {
	KeyID      KeyID             `json:"id"`
	Algorithm  AlgorithmID       `json:"algorithm"`
	Operations []Operation       `json:"operations"`
	State      KeyState          `json:"state"`
	PublicKey  crypto.PublicKey  `json:"-"` // serialized via MarshalJSON
	CreatedAt  time.Time         `json:"created_at"`
	NotBefore  *time.Time        `json:"not_before,omitempty"`
	NotAfter   *time.Time        `json:"not_after,omitempty"`
	Origin     KeyOrigin         `json:"origin"`
	Tags       map[string]string `json:"tags,omitempty"`
	PolicyID   string            `json:"policy_id,omitempty"`
}

type BackupBlob struct {
	Bytes []byte
}

// MarshalJSON serializes KeyMetadata, encoding PublicKey as a PEM string.
// type plain breaks the MarshalJSON recursion; the outer PublicKey string
// field shadows the json:"-" field from the embedded plain.
func (m KeyMetadata) MarshalJSON() ([]byte, error) {
	type plain KeyMetadata
	return json.Marshal(struct {
		plain
		PublicKey string `json:"public_key,omitempty"`
	}{plain(m), encodePubKey(m.PublicKey)})
}

// encodePubKey converts a crypto.PublicKey to a PEM string, falling back to
// raw base64 for types not yet supported by x509 (e.g. ML-KEM).
func encodePubKey(pub crypto.PublicKey) string {
	if pub == nil {
		return ""
	}
	if der, err := x509.MarshalPKIXPublicKey(pub); err == nil {
		return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	}
	type byter interface{ Bytes() []byte }
	if b, ok := pub.(byter); ok {
		return base64.StdEncoding.EncodeToString(b.Bytes())
	}
	return ""
}
