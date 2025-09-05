package models

import (
	"time"
)

// KMS
type Key struct {
	ID         string            `json:"id"`
	Algorithm  string            `json:"algorithm"`
	Size       int               `json:"size"`
	PublicKey  string            `json:"public_key"`
	Status     CertificateStatus `json:"status"`
	CreationTS time.Time         `json:"creation_ts"`
	Name       string            `json:"name"`
}

type MessageSignature struct {
	Signature string `json:"signature"`
}

type MessageValidation struct {
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
}
