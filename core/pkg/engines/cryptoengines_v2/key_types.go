package cryptoenginesv2

import (
	"crypto"
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
	KeyID      KeyID
	Algorithm  AlgorithmID
	Operations []Operation
	State      KeyState
	PublicKey  crypto.PublicKey
	CreatedAt  time.Time
	NotBefore  *time.Time
	NotAfter   *time.Time
	Origin     KeyOrigin
	Tags       map[string]string
	PolicyID   string
}

type BackupBlob struct {
	Bytes []byte
}
