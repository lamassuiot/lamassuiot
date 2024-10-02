package models

type AsymmetricCryptoKey struct {
	KeyID     string  `json:"kid"`
	EngineID  string  `json:"engine_id"`
	PublicKey string  `json:"public_key"`
	Algorithm KeyType `json:"algorithm"`
}
