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

	ListPrivateKeyIDs() ([]KeyID, error)
	GetPrivateKeyByID(keyID KeyID) (crypto.Signer, error)

	CreateRSAPrivateKey(keySize int) (KeyID, crypto.Signer, error)
	CreateECDSAPrivateKey(curve elliptic.Curve) (KeyID, crypto.Signer, error)

	ImportRSAPrivateKey(key *rsa.PrivateKey) (KeyID, crypto.Signer, error)
	ImportECDSAPrivateKey(key *ecdsa.PrivateKey) (KeyID, crypto.Signer, error)

	DeleteKey(keyID KeyID) error

	RenameKey(oldID, newID KeyID) error
}

var cryptoEngineBuilders = make(map[config.CryptoEngineProvider]func(*logrus.Entry, config.CryptoEngineConfig) (CryptoEngine, error))

func RegisterCryptoEngine(name config.CryptoEngineProvider, builder func(*logrus.Entry, config.CryptoEngineConfig) (CryptoEngine, error)) {
	cryptoEngineBuilders[name] = builder
}

func GetEngineBuilder(name config.CryptoEngineProvider) func(*logrus.Entry, config.CryptoEngineConfig) (CryptoEngine, error) {
	return cryptoEngineBuilders[name]
}
