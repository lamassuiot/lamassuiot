package services

import (
	"context"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
)

type KMSService interface {
	GetCryptoEngineProvider(ctx context.Context) ([]*models.CryptoEngineProvider, error)

	GetKeys(ctx context.Context, input GetKeysInput) (string, error)
	GetKey(ctx context.Context, input GetKeyInput) (*models.Key, error)

	CreateKey(ctx context.Context, input CreateKeyInput) (*models.Key, error)
	ImportKey(ctx context.Context, input ImportKeyInput) (*models.Key, error)

	UpdateKeyMetadata(ctx context.Context, input UpdateKeyMetadataInput) (*models.Key, error)
	UpdateKeyAliases(ctx context.Context, input UpdateKeyAliasesInput) (*models.Key, error)
	UpdateKeyName(ctx context.Context, input UpdateKeyNameInput) (*models.Key, error)
	UpdateKeyTags(ctx context.Context, input UpdateKeyTagsInput) (*models.Key, error)

	DeleteKeyByID(ctx context.Context, input GetKeyInput) error

	SignMessage(ctx context.Context, input SignMessageInput) (*models.MessageSignature, error)
	VerifySignature(ctx context.Context, input VerifySignInput) (*models.MessageValidation, error)
}

// Identifier can be either KeyID, Alias, or PKCS11URI
type GetKeyInput struct {
	Identifier string `validate:"required"`
}

type GetKeysInput struct {
	resources.ListInput[models.Key]
}

type CreateKeyInput struct {
	Algorithm string `validate:"required"`
	Size      int    `validate:"required"`
	EngineID  string
	Name      string `validate:"required"`
	Tags      []string
	Metadata  map[string]any
}

// Identifier can be either KeyID, Alias, or PKCS11URI
type SignMessageInput struct {
	Identifier  string                 `validate:"required"`
	Algorithm   string                 `validate:"required"`
	Message     []byte                 `validate:"required"`
	MessageType models.SignMessageType `validate:"required"`
	Certificate string				 
}

type VerifySignInput struct {
	Identifier  string                 `validate:"required"`
	Algorithm   string                 `validate:"required"`
	Signature   []byte                 `validate:"required"`
	Message     []byte                 `validate:"required"`
	MessageType models.SignMessageType `validate:"required"`
}

type ImportKeyInput struct {
	PrivateKey any `validate:"required"`
	EngineID   string
	Name       string
	Tags       []string
	Metadata   map[string]any
}

type UpdateKeyMetadataInput struct {
	ID      string                  `validate:"required"`
	Patches []models.PatchOperation `validate:"required"`
}

type UpdateKeyAliasesInput struct {
	ID      string                  `validate:"required"`
	Patches []models.PatchOperation `validate:"required"`
}

type UpdateKeyNameInput struct {
	ID   string `validate:"required"`
	Name string `validate:"required"`
}

type UpdateKeyTagsInput struct {
	ID   string   `validate:"required"`
	Tags []string `validate:"required"`
}

type UpdateKeyIDInput struct {
	CurrentID string `validate:"required"`
	NewID     string `validate:"required"`
}
