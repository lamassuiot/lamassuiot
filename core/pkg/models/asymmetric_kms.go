package models

import (
	"crypto/x509"
	"time"
)

type SignMessageType string

const (
	Raw    SignMessageType = "raw"
	Hashed SignMessageType = "hash"
)

type KeyPair struct {
	KeyID       string
	Algorithm   x509.PublicKeyAlgorithm
	KeySize     int
	KeyStrength KeyStrength
	EngineID    string
	PublicKey   X509PublicKey
	HasPrivate  bool
	CreatedAt   time.Time
	Imported    bool
	Exported    bool
}

type KMSStats struct {
	TotalKeyPairs     int
	KeyPairsPerEngine map[string]int
}
