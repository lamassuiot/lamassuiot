package cryptoenginesv2

import "time"

// CreateKeyRequest is the body for POST /v2/kms/keys.
// When KeyMaterial is non-empty the server treats it as an import (ImportKey);
// otherwise a new key is generated (CreateKey).
type CreateKeyRequest struct {
	Algorithm   AlgorithmID       `json:"algorithm" binding:"required"`
	Operations  []Operation       `json:"operations"`
	Tags        map[string]string `json:"tags"`
	PolicyID    string            `json:"policy_id"`
	NotBefore   *time.Time        `json:"not_before"`
	NotAfter    *time.Time        `json:"not_after"`
	BackendHint string            `json:"backend_hint"`
	// KeyMaterial is a base64-encoded PKCS#8 DER blob (asymmetric) or raw key
	// bytes (symmetric). Present only for the import path.
	KeyMaterial string `json:"key_material"`
}

// UpdateKeyRequest is the body for PATCH /v2/kms/keys/{id}.
// Only the fields that are explicitly set (non-nil) are patched.
type UpdateKeyRequest struct {
	Tags     map[string]string `json:"tags"`
	PolicyID    *string           `json:"policy_id"`
	NotAfter    *time.Time        `json:"not_after"`
}

// SetKeyStateRequest is the body for PUT /v2/kms/keys/{id}/state.
// Valid target states: enabled, disabled, pendingDeletion.
// DeletionScheduledAt is required when State is pendingDeletion.
type SetKeyStateRequest struct {
	State               KeyState   `json:"state" binding:"required"`
	DeletionScheduledAt *time.Time `json:"deletion_scheduled_at"`
}

// RestoreKeyRequest is the body for POST /v2/kms/keys/restore.
type RestoreKeyRequest struct {
	BackupBlob string `json:"backup_blob" binding:"required"` // base64-encoded BackupBlob.Bytes
}

// UpsertAliasRequest is the body for PUT /v2/kms/aliases/{name}.
// Creates or retargets the alias atomically.
type UpsertAliasRequest struct {
	KeyID string `json:"key_id" binding:"required"`
}

// GenerateRandomRequest is the body for POST /v2/kms/random.
type GenerateRandomRequest struct {
	Bytes int `json:"bytes" binding:"required,min=1,max=1024"`
}
