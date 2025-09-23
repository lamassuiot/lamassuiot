package models

import (
	"crypto/x509"
	"encoding/json"
)

type KeyStrength string

const (
	KeyStrengthHigh   KeyStrength = "HIGH"
	KeyStrengthMedium KeyStrength = "MEDIUM"
	KeyStrengthLow    KeyStrength = "LOW"
)

type KeyType x509.PublicKeyAlgorithm

type KeyMetadata struct {
	KeyID string  `json:"key_id"`
	Type  KeyType `json:"type" gorm:"serializer:text"`
	Bits  int     `json:"bits"`
}

type KeyStrengthMetadata struct {
	Type     KeyType     `json:"type" gorm:"serializer:text"`
	Bits     int         `json:"bits"`
	Strength KeyStrength `json:"strength"`
}

//---------------------------------------

func (kt KeyType) String() string {
	publicKeyAlg := x509.PublicKeyAlgorithm(kt)
	return publicKeyAlg.String()
}

func (kt KeyType) MarshalText() ([]byte, error) {
	return []byte(kt.String()), nil
}

func (kt *KeyType) UnmarshalText(text []byte) error {
	k, err := ParseKeyType(string(text))
	if err != nil {
		return err
	}

	*kt = *k
	return nil
}

func (kt KeyType) MarshalJSON() ([]byte, error) {
	str := kt.String()
	return json.Marshal(str)
}

func (kt *KeyType) UnmarshalJSON(data []byte) error {
	var t string
	err := json.Unmarshal(data, &t)
	if err != nil {
		return err
	}

	nkt, err := ParseKeyType(t)
	if err != nil {
		return err
	}

	*kt = *nkt
	return nil
}

func ParseKeyType(s string) (*KeyType, error) {
	var nkt KeyType

	switch s {
	case "UNKNOWN":
		nkt = KeyType(x509.UnknownPublicKeyAlgorithm)
	case "RSA":
		nkt = KeyType(x509.RSA)
	case "DSA":
		nkt = KeyType(x509.DSA)
	case "ECDSA":
		nkt = KeyType(x509.ECDSA)
	case "Ed25519":
		nkt = KeyType(x509.Ed25519)
	case "ML-DSA":
		nkt = KeyType(x509.MLDSA)
	default:
		nkt = KeyType(x509.UnknownPublicKeyAlgorithm)
	}

	return &nkt, nil
}
