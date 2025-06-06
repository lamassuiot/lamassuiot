package models

type KeyInfo struct {
	ID        string `json:"id"`
	Algorithm string `json:"algorithm"`
	Size      string `json:"size"`
	PublicKey string `json:"publicKey"`
}

type MessageSignature struct {
	Signature string `json:"signature"`
}
