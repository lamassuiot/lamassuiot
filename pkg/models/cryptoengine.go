package models

type CryptoEngineProvider struct {
	Provider          string                 `json:"provider"`
	Manufacturer      string                 `json:"manufacturer"`
	Model             string                 `json:"model"`
	SupportedKeyTypes []SupportedKeyTypeInfo `json:"supported_key_types"`
}

type EngineProvider struct {
	ID       string                 `json:"id"`
	Name     string                 `json:"name"`
	Metadata map[string]interface{} `json:"metadata"`
	CryptoEngineProvider
}

type SupportedKeyTypeInfo struct {
	Type        KeyType `json:"type"`
	MinimumSize int     `json:"min_size"`
	MaximumSize int     `json:"max_size"`
}
