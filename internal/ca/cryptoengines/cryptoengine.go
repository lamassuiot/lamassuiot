package cryptoengines

import (
	"crypto"
	"crypto/elliptic"

	"github.com/lamassuiot/lamassuiot/pkg/models"
)

type CryptoEngine interface {
	GetEngineConfig() models.CryptoEngineProvider

	GetPrivateKeyByID(string) (crypto.Signer, error)

	CreateRSAPrivateKey(keySize int, keyID string) (crypto.Signer, error)
	CreateECDSAPrivateKey(curve elliptic.Curve, keyID string) (crypto.Signer, error)

	DeleteAllKeys() error
}
