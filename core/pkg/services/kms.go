package services

import (
	"context"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
)

type KMSService interface {
	GetCryptoEngineProvider(ctx context.Context) ([]*models.CryptoEngineProvider, error)

	GetKeys(ctx context.Context, input GetKeysInput) (string, error)
	GetKeyByID(ctx context.Context, input GetKeyByIDInput) (*models.Key, error)

	CreateKey(ctx context.Context, input CreateKeyInput) (*models.Key, error)
	ImportKey(ctx context.Context, input ImportKeyInput) (*models.Key, error)

	UpdateKeyMetadata(ctx context.Context, input UpdateKeyMetadataInput) (*models.Key, error)
	UpdateKeyAlias(ctx context.Context, input UpdateKeyAliasInput) (*models.Key, error)
	UpdateKeyID(ctx context.Context, input UpdateKeyIDInput) (*models.Key, error)

	DeleteKeyByID(ctx context.Context, input GetKeyByIDInput) error

	SignMessage(ctx context.Context, input SignMessageInput) (*models.MessageSignature, error)
	VerifySignature(ctx context.Context, input VerifySignInput) (*models.MessageValidation, error)
}

type GetKeyByIDInput struct {
	ID string `validate:"required"`
}

type GetKeysInput struct {
	resources.ListInput[models.Key]
}

type CreateKeyInput struct {
	Algorithm string `validate:"required"`
	Size      int    `validate:"required"`
	EngineID  string
	Name      string `validate:"required"`
}

type SignMessageInput struct {
	KeyID       string                 `validate:"required"`
	Algorithm   string                 `validate:"required"`
	Message     []byte                 `validate:"required"`
	MessageType models.SignMessageType `validate:"required"`
}

type VerifySignInput struct {
	KeyID       string                 `validate:"required"`
	Algorithm   string                 `validate:"required"`
	Signature   []byte                 `validate:"required"`
	Message     []byte                 `validate:"required"`
	MessageType models.SignMessageType `validate:"required"`
}

type ImportKeyInput struct {
	PrivateKey any `validate:"required"`
	EngineID   string
	Name       string `validate:"required"`
}

type UpdateKeyMetadataInput struct {
	ID      string                  `validate:"required"`
	Patches []models.PatchOperation `validate:"required"`
}

type UpdateKeyAliasInput struct {
	ID    string `validate:"required"`
	Alias string `validate:"required"`
}

type UpdateKeyIDInput struct {
	CurrentID string `validate:"required"`
	NewID     string `validate:"required"`
}
