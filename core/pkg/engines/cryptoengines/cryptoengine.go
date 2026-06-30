package cryptoengines

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
)

type CryptoEngine interface {
	GetEngineConfig() models.CryptoEngineInfo

	ListPrivateKeyIDs(ctx context.Context) ([]string, error)
	GetPrivateKeyByID(ctx context.Context, keyID string) (crypto.Signer, error)

	CreateRSAPrivateKey(ctx context.Context, keySize int) (string, crypto.Signer, error)
	CreateECDSAPrivateKey(ctx context.Context, curve elliptic.Curve) (string, crypto.Signer, error)

	ImportRSAPrivateKey(ctx context.Context, key *rsa.PrivateKey) (string, crypto.Signer, error)
	ImportECDSAPrivateKey(ctx context.Context, key *ecdsa.PrivateKey) (string, crypto.Signer, error)

	DeleteKey(ctx context.Context, keyID string) error

	RenameKey(ctx context.Context, oldID, newID string) error
}

var cryptoEngineBuilders = make(map[config.CryptoEngineProvider]func(*logrus.Entry, config.CryptoEngineConfig) (CryptoEngine, error))

func RegisterCryptoEngine(name config.CryptoEngineProvider, builder func(*logrus.Entry, config.CryptoEngineConfig) (CryptoEngine, error)) {
	cryptoEngineBuilders[name] = builder
}

func GetEngineBuilder(name config.CryptoEngineProvider) func(*logrus.Entry, config.CryptoEngineConfig) (CryptoEngine, error) {
	return cryptoEngineBuilders[name]
}
