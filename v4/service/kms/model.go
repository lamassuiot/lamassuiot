package kms

import (
	"time"
)

type Key struct {
	ID         string         `json:"id"`
	Algorithm  string         `json:"algorithm"`
	Size       int            `json:"size"`
	PublicKey  string         `json:"public_key"`
	CreationTS time.Time      `json:"creation_ts"`
	Name       string         `json:"name"`
	Metadata   map[string]any `json:"metadata,omitempty"  gorm:"serializer:json"`
}

type MessageSignature struct {
	Signature string `json:"signature"`
}

type MessageValidation struct {
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
}
