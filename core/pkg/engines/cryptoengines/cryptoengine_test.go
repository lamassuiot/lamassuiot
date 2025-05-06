package cryptoengines

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type mockCryptoEngine struct{}

func (m *mockCryptoEngine) GetEngineConfig() models.CryptoEngineInfo {
	return models.CryptoEngineInfo{}
}

func (m *mockCryptoEngine) GetPrivateKeyByID(keyID KeyID) (crypto.Signer, error) {
	return nil, nil
}

func (m *mockCryptoEngine) ListPrivateKeyIDs() ([]KeyID, error) {
	return nil, nil
}

func (m *mockCryptoEngine) CreateRSAPrivateKey(keySize int) (KeyID, crypto.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, keySize)
	return "", key, err
}

func (m *mockCryptoEngine) CreateECDSAPrivateKey(curve elliptic.Curve) (KeyID, crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	return "", key, err
}

func (m *mockCryptoEngine) ImportRSAPrivateKey(key *rsa.PrivateKey) (KeyID, crypto.Signer, error) {
	return "", key, nil
}

func (m *mockCryptoEngine) ImportECDSAPrivateKey(key *ecdsa.PrivateKey) (KeyID, crypto.Signer, error) {
	return "", key, nil
}

func (m *mockCryptoEngine) DeleteKey(keyID KeyID) error {
	return nil
}

func (m *mockCryptoEngine) RenameKey(keyID KeyID, newKeyID KeyID) error {
	return nil
}

func TestRegisterCryptoEngine(t *testing.T) {
	builder := func(logger *logrus.Entry, config config.CryptoEngineConfig) (CryptoEngine, error) {
		return &mockCryptoEngine{}, nil
	}
	RegisterCryptoEngine(config.CryptoEngineProvider("mock"), builder)
	assert.NotNil(t, cryptoEngineBuilders[config.CryptoEngineProvider("mock")])
}

func TestGetEngineBuilder(t *testing.T) {
	builder := func(logger *logrus.Entry, config config.CryptoEngineConfig) (CryptoEngine, error) {
		return &mockCryptoEngine{}, nil
	}
	RegisterCryptoEngine(config.CryptoEngineProvider("mock"), builder)
	retrievedBuilder := GetEngineBuilder(config.CryptoEngineProvider("mock"))
	assert.NotNil(t, retrievedBuilder)
}
