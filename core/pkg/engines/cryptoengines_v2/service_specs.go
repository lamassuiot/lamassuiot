package cryptoenginesv2

import "time"

type CreateKeySpec struct {
	KeyID       KeyID // assigned by Service before calling Backend
	Algorithm   AlgorithmID
	Operations  []Operation
	Description string
	Tags        map[string]string
	PolicyID    string
	NotBefore   *time.Time
	NotAfter    *time.Time
	BackendHint string
}

type ImportKeySpec struct {
	KeyID       KeyID
	Algorithm   AlgorithmID
	Operations  []Operation
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
