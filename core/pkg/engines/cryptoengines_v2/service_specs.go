package cryptoenginesv2

import "time"

type CreateKeySpec struct {
	KeyID   KeyID // assigned by Service before calling Backend
	KeySpec KeySpec
	// Operations is the fine-grained authorization set persisted on the key.
	// If empty and KeyUsages is set, the Service expands KeyUsages into it.
	Operations  []Operation
	KeyUsages   []KeyUsage // optional coarse usages, expanded into Operations
	Description string
	Tags        map[string]string
	PolicyID    string
	NotBefore   *time.Time
	NotAfter    *time.Time
	BackendHint string
}

type ImportKeySpec struct {
	KeyID       KeyID
	KeySpec     KeySpec
	Operations  []Operation
	KeyUsages   []KeyUsage
	KeyMaterial []byte // plain canonical encoding (PKCS#8 / raw bytes)
	Description string
	Tags        map[string]string
	PolicyID    string
	NotBefore   *time.Time
	NotAfter    *time.Time
	BackendHint string
}

type KeyPatch struct {
	Description *string
	Tags        map[string]string
	PolicyID    *string
	NotAfter    *time.Time
}

type ListOpts struct {
	PageToken string
	PageSize  int
	Filter    string
}

type ListKeysResult struct {
	Keys          []KeyMetadata
	NextPageToken string
}
