package models

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
)

type KeyStrength string

const (
	KeyStrengthHigh   KeyStrength = "HIGH"
	KeyStrengthMedium KeyStrength = "MEDIUM"
	KeyStrengthLow    KeyStrength = "LOW"
)

type KeyType x509.PublicKeyAlgorithm

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

func (kt KeyType) String() string {
	publicKeyAlg := x509.PublicKeyAlgorithm(kt)
	return publicKeyAlg.String()
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

	var nkt KeyType

	switch string(t) {
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
	default:
		return fmt.Errorf("unknown key type")
	}

	*kt = nkt
	return nil
}
