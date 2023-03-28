package models

import (
	"crypto/ecdsa"
	"crypto/rsa"
)

type KeyStrength string

const (
	KeyStrengthHigh   KeyStrength = "HIGH"
	KeyStrengthMedium KeyStrength = "MEDIUM"
	KeyStrengthLow    KeyStrength = "LOW"
)

type KeyType string

const (
	RSA   KeyType = "RSA"
	ECDSA KeyType = "ECDSA"
)

type KeyMetadata struct {
	Type KeyType `json:"type"`
	Bits int     `json:"bits"`
}

type KeyStrengthMetadata struct {
	Type     KeyType     `json:"type"`
	Bits     int         `json:"bits"`
	Strength KeyStrength `json:"strength"`
}

//---------------------------------------

type PrivateKey interface {
	rsa.PrivateKey | ecdsa.PrivateKey
}
