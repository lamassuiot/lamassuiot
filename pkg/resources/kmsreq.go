package resources

import "github.com/lamassuiot/lamassuiot/v2/pkg/models"

type CreatePrivateKeyBody struct {
	EngineID     string         `json:"engine_id"`
	KeyAlgorithm models.KeyType `json:"algorithm"`
	KeySize      int            `json:"key_size"`
}
type ImportPrivateKey struct {
	EngineID   string `json:"engine_id"`
	PrivateKey string `json:"private_key"` //b64 from PEM
}
