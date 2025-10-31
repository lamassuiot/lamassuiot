package models

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

// KMS
type Key struct {
	PKCS11URI     string         `json:"pkcs11_uri" gorm:"-"`
	KeyID         string         `json:"key_id"`
	Name          string         `json:"name"`
	Aliases       []string       `json:"aliases" gorm:"serializer:json"`
	EngineID      string         `json:"engine_id"`
	HasPrivateKey bool           `json:"has_private_key"`
	Algorithm     string         `json:"algorithm"`
	Size          int            `json:"size"`
	PublicKey     string         `json:"public_key"`
	CreationTS    time.Time      `json:"creation_ts"`
	Metadata      map[string]any `json:"metadata" gorm:"serializer:json"`
}

func (k *Key) AfterFind(tx *gorm.DB) (err error) {
	keyType := "public"
	if k.HasPrivateKey {
		keyType = "private"
	}

	k.PKCS11URI = fmt.Sprintf("pkcs11:token-id=%s;id=%s;type=%s", k.EngineID, k.KeyID, keyType)
	return nil
}

type MessageSignature struct {
	Signature string `json:"signature"`
}

type MessageValidation struct {
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
}
