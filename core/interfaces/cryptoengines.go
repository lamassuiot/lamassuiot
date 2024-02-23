package interfaces

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"

	"github.com/lamassuiot/lamassuiot/v2/core/pkg/models"
	"github.com/sirupsen/logrus"
)

type CryptoEngineBuilder interface {
	NewCryptoEngine(logger *logrus.Entry, config any) (CryptoEngine, error)
}

type CryptoEngine interface {
	GetEngineConfig() models.CryptoEngineInfo

	GetPrivateKeyByID(keyID string) (crypto.Signer, error)

	CreateRSAPrivateKey(keySize int, keyID string) (crypto.Signer, error)
	CreateECDSAPrivateKey(curve elliptic.Curve, keyID string) (crypto.Signer, error)

	ImportRSAPrivateKey(key *rsa.PrivateKey, keyID string) (crypto.Signer, error)
	ImportECDSAPrivateKey(key *ecdsa.PrivateKey, keyID string) (crypto.Signer, error)
}
