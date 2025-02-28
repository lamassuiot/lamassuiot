package services

import (
	"context"
	"crypto/x509"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
)

type AsymmetricKMSService interface {
	CreateKeyPair(ctx context.Context, input CreateKeyPairInput) (*models.KeyPair, error)
	ImportKeyPair(ctx context.Context, input ImportKeyPairInput) (*models.KeyPair, error)

	ExportPrivateKey(ctx context.Context, input ExportPrivateKeyInput) ([]byte, error)
	//ExportPrivateKeyWithWrapping(ctx context.Context, keyID string) ([]byte, error)

	DeleteKeyPair(ctx context.Context, input DeleteKeyPairInput) error

	GetKeyPair(ctx context.Context, input GetKeyPairInput) (*models.KeyPair, error)
	GetKeyPairs(ctx context.Context, input GetKeyPairsInput) (string, error)

	Stats(ctx context.Context) (models.KMSStats, error)

	Sign(ctx context.Context, input KMSSignInput) ([]byte, error)
	Verify(ctx context.Context, input VerifyInput) (bool, error)
}

type GetKetPairsInput struct {
	QueryParameters *resources.QueryParameters

	ExhaustiveRun bool //wether to iter all elems
	ApplyFunc     func(kp models.KeyPair)
}

type CreateKeyPairInput struct {
	EngineID  string
	Algorithm x509.PublicKeyAlgorithm
	KeySize   int
}

type ImportKeyPairInput struct {
	EngineID   string
	PublicKey  models.X509PublicKey
	PrivateKey models.X509PrivateKey
}

type ExportPrivateKeyInput struct {
	KeyID string
}

type DeleteKeyPairInput struct {
	KeyID string
}

type GetKeyPairInput struct {
	KeyID string
}

type GetKeyPairsInput struct {
	QueryParameters *resources.QueryParameters

	ExhaustiveRun bool //wether to iter all elems
	ApplyFunc     func(kp models.KeyPair)
}

type KMSSignInput struct {
	KeyID              string
	Message            []byte
	MessageType        models.SignMessageType
	SignatureAlgorithm x509.SignatureAlgorithm
}

type VerifyInput struct {
	KeyID              string
	Signature          []byte
	Message            []byte
	MessageType        models.SignMessageType
	SignatureAlgorithm x509.SignatureAlgorithm
}
