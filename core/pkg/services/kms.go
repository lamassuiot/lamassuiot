package services

import (
	"context"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

type KMSService interface {
	GetKeys(ctx context.Context) ([]*models.KeyInfo, error)
	GetKeyByID(ctx context.Context, input GetByIDInput) (*models.KeyInfo, error)
	CreateKey(ctx context.Context, input CreateKeyInput) (*models.KeyInfo, error)
	DeleteKeyByID(ctx context.Context, input GetByIDInput) error
	SignMessage(ctx context.Context, input SignMessageInput) (*models.MessageSignature, error)
	VerifySignature(ctx context.Context, input VerifySignInput) (bool, error)
	ImportKey(ctx context.Context, input ImportKeyInput) (*models.KeyInfo, error)
}

type CreateKeyInput struct {
	Algorithm string `validate:"required"`
	Size      string `validate:"required"`
}

type SignMessageInput struct {
	KeyID     string `validate:"required"`
	Algorithm string `validate:"required"`
	Message   []byte `validate:"required"`
}

type VerifySignInput struct {
	KeyID     string `validate:"required"`
	Algorithm string `validate:"required"`
	Signature []byte `validate:"required"`
	Message   []byte `validate:"required"`
}

type ImportKeyInput struct {
	PrivateKey []byte `validate:"required"`
}
