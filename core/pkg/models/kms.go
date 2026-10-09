package models

import (
	"encoding/base64"
	"fmt"
	"strings"
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
	Tags          []string       `json:"tags" gorm:"serializer:json"`
	Metadata      map[string]any `json:"metadata" gorm:"serializer:json"`
}

// BuildPKCS11ID builds the PKCS#11 URI used to identify a key within a crypto engine:
// pkcs11:token-id=<engineID>;id=<keyID>;type=<keyType>
func BuildPKCS11ID(engineID, keyID, keyType string) string {
	return "pkcs11:token-id=" + engineID + ";id=" + keyID + ";type=" + keyType
}

func (k *Key) AfterFind(tx *gorm.DB) (err error) {
	keyType := "public"
	if k.HasPrivateKey {
		keyType = "private"
	}

	k.PKCS11URI = BuildPKCS11ID(k.EngineID, k.KeyID, keyType)
	return nil
}

type Signature []byte

func (c *Signature) String() string {
	return base64.StdEncoding.EncodeToString(*c)
}

func (c *Signature) UnmarshalText(text []byte) error {
	decoded, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return err
	}

	*c = Signature(decoded)
	return nil
}

type MessageSignature struct {
	Signature Signature `json:"signature"`
}

type MessageValidation struct {
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
}

type KeyStats struct {
	TotalKeys                    int            `json:"total_keys"`
	KeysDistributionPerEngine    map[string]int `json:"keys_distribution_per_engine"`
	KeysDistributionPerAlgorithm map[string]int `json:"keys_distribution_per_algorithm"`
}

func ParsePKCS11URI(uri string) (map[string]string, error) {
	result := make(map[string]string)

	// Strip the scheme ("pkcs11:") if present
	uri = strings.TrimPrefix(uri, "pkcs11:")

	// Split key=value pairs by ";"
	parts := strings.Split(uri, ";")
	for _, part := range parts {
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid part: %s", part)
		}
		key := kv[0]
		val := kv[1]
		result[key] = val
	}

	return result, nil
}
