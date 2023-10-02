package models

type CryptoEngineType string

const (
	PKCS11            CryptoEngineType = "PKCS11"
	AzureKeyVault     CryptoEngineType = "AZURE_KEY_VAULT"
	Golang            CryptoEngineType = "GOLANG"
	VaultKV2          CryptoEngineType = "HASHICORP_VAULT_KV_V2"
	AWSKMS            CryptoEngineType = "AWS_KMS"
	AWSSecretsManager CryptoEngineType = "AWS_SECRETS_MANAGER"
)

type CryptoEngineSL int

const (
	SL0 CryptoEngineSL = 0
	SL1 CryptoEngineSL = 1
	SL2 CryptoEngineSL = 2
)

type CryptoEngineInfo struct {
	Type              CryptoEngineType       `json:"type"`
	SecurityLevel     CryptoEngineSL         `json:"security_level"`
	Provider          string                 `json:"provider"`
	Name              string                 `json:"name"`
	Metadata          map[string]any         `json:"metadata"`
	SupportedKeyTypes []SupportedKeyTypeInfo `json:"supported_key_types"`
}

type CryptoEngineProvider struct {
	CryptoEngineInfo
	ID      string `json:"id"`
	Default bool   `json:"default"`
}

type SupportedKeyTypeInfo struct {
	Type  KeyType `json:"type"`
	Sizes []int   `json:"sizes"`
}
