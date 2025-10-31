package models

import (
	"time"
)

// KMS
type Key struct {
	PKCS11URI  string            `json:"pkcs11_uri"`
	ID         string            `json:"id"`
	Algorithm  string            `json:"algorithm"`
	Size       int               `json:"size"`
	PublicKey  string            `json:"public_key"`
	Status     CertificateStatus `json:"status"`
	CreationTS time.Time         `json:"creation_ts"`
	Name       string            `json:"name"`
	Metadata   map[string]any    `json:"metadata,omitempty"  gorm:"serializer:json"`
}

type MessageSignature struct {
	Signature string `json:"signature"`
}

type MessageValidation struct {
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
}
