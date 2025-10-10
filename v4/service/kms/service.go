package kms

import (
	"context"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
)

const SHORT_SERVICE_IDENTIFIER = "KMS"
const SERVICE_SOURCE = "service/kms"

type KMSMiddleware func(KMSService) KMSService

type KMSService interface {
	GetKeys(ctx context.Context, input GetKeysInput) (string, error)
	GetKeyByID(ctx context.Context, input GetKeyByIDInput) (*Key, error)
	CreateKey(ctx context.Context, input CreateKeyInput) (*Key, error)
	ImportKey(ctx context.Context, input ImportKeyInput) (*Key, error)
	DeleteKeyByID(ctx context.Context, input GetKeyByIDInput) error
	SignMessage(ctx context.Context, input SignMessageInput) (*MessageSignature, error)
	VerifySignature(ctx context.Context, input VerifySignInput) (*MessageValidation, error)
}

type SignMessageType string

const (
	SignMessageTypeRaw    SignMessageType = "raw"
	SignMessageTypeHashed SignMessageType = "hash"
)

type GetKeyByIDInput struct {
	ID string `validate:"required"`
}

type GetKeysInput struct {
	resources.ListInput[Key]
}

type CreateKeyInput struct {
	Algorithm string `validate:"required"`
	Size      int    `validate:"required"`
	EngineID  string
	Name      string `validate:"required"`
}

type SignMessageInput struct {
	KeyID       string          `validate:"required"`
	Algorithm   string          `validate:"required"`
	Message     []byte          `validate:"required"`
	MessageType SignMessageType `validate:"required"`
}

type VerifySignInput struct {
	KeyID       string          `validate:"required"`
	Algorithm   string          `validate:"required"`
	Signature   []byte          `validate:"required"`
	Message     []byte          `validate:"required"`
	MessageType SignMessageType `validate:"required"`
}

type ImportKeyInput struct {
	PrivateKey any `validate:"required"`
	EngineID   string
	Name       string `validate:"required"`
}
