package cryptoengines

import (
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

	ListPrivateKeyIDs() ([]string, error)
	GetPrivateKeyByID(keyID string) (crypto.Signer, error)

	CreateRSAPrivateKey(keySize int) (string, crypto.Signer, error)
	CreateECDSAPrivateKey(curve elliptic.Curve) (string, crypto.Signer, error)
	CreateMLDSAPrivateKey(dimensions int) (string, crypto.Signer, error)

	ImportRSAPrivateKey(key *rsa.PrivateKey) (string, crypto.Signer, error)
	ImportECDSAPrivateKey(key *ecdsa.PrivateKey) (string, crypto.Signer, error)

	DeleteKey(keyID string) error

	RenameKey(oldID, newID string) error
}

var cryptoEngineBuilders = make(map[config.CryptoEngineProvider]func(*logrus.Entry, config.CryptoEngineConfig) (CryptoEngine, error))

func RegisterCryptoEngine(name config.CryptoEngineProvider, builder func(*logrus.Entry, config.CryptoEngineConfig) (CryptoEngine, error)) {
	cryptoEngineBuilders[name] = builder
}

func GetEngineBuilder(name config.CryptoEngineProvider) func(*logrus.Entry, config.CryptoEngineConfig) (CryptoEngine, error) {
	return cryptoEngineBuilders[name]
}
