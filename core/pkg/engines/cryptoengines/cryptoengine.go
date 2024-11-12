package cryptoengines

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"

	"github.com/lamassuiot/lamassuiot/v3/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/models"
	"github.com/sirupsen/logrus"
)

type CryptoEngine interface {
	GetEngineConfig() models.CryptoEngineInfo

	GetPrivateKeyByID(keyID string) (crypto.Signer, error)

	CreateRSAPrivateKey(keySize int, keyID string) (crypto.Signer, error)
	CreateECDSAPrivateKey(curve elliptic.Curve, keyID string) (crypto.Signer, error)

	ImportRSAPrivateKey(key *rsa.PrivateKey, keyID string) (crypto.Signer, error)
	ImportECDSAPrivateKey(key *ecdsa.PrivateKey, keyID string) (crypto.Signer, error)
}

var cryptoEngineBuilders = make(map[config.CryptoEngineProvider]func(*logrus.Entry, config.CryptoEngine) (CryptoEngine, error))

func RegisterCryptoEngine(name config.CryptoEngineProvider, builder func(*logrus.Entry, config.CryptoEngine) (CryptoEngine, error)) {
	cryptoEngineBuilders[name] = builder
}

func GetEngineBuilder(name config.CryptoEngineProvider) func(*logrus.Entry, config.CryptoEngine) (CryptoEngine, error) {
	return cryptoEngineBuilders[name]
}
