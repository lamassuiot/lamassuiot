package cryptoengines

import (
	"crypto"
	"crypto/elliptic"

	"github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
)

type CryptoEngine interface {
	GetEngineConfig() api.EngineProviderInfo
	// GetPrivateKeys() ([]crypto.Signer, error)
	// DeleteAllKeys() error
	GetPrivateKeyByID(string) (crypto.Signer, error)
	CreateRSAPrivateKey(keySize int, keyID string) (crypto.Signer, error)
	CreateECDSAPrivateKey(curve elliptic.Curve, keyID string) (crypto.Signer, error)
}
