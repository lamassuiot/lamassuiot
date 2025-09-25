package cryptoengines

import (
	"cloudflare/circl/sign/mldsa/mldsa44"
	"cloudflare/circl/sign/mldsa/mldsa65"
	"cloudflare/circl/sign/mldsa/mldsa87"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
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

func (m *mockCryptoEngine) GetPrivateKeyByID(keyID string) (crypto.Signer, error) {
	return nil, nil
}

func (m *mockCryptoEngine) ListPrivateKeyIDs() ([]string, error) {
	return nil, nil
}

func (m *mockCryptoEngine) CreateRSAPrivateKey(keySize int) (string, crypto.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, keySize)
	return "", key, err
}

func (m *mockCryptoEngine) CreateECDSAPrivateKey(curve elliptic.Curve) (string, crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	return "", key, err
}

func (m *mockCryptoEngine) CreateMLDSAPrivateKey(dimensions int) (string, crypto.Signer, error) {
	var key crypto.Signer
	var err error
	switch dimensions {
	case 44:
		_, key, err = mldsa44.GenerateKey(rand.Reader)
	case 65:
		_, key, err = mldsa65.GenerateKey(rand.Reader)
	case 87:
		_, key, err = mldsa87.GenerateKey(rand.Reader)
	default:
		err = errors.New("unsupported dimensions")
	}
	return "", key, err
}

func (m *mockCryptoEngine) CreateEd25519PrivateKey() (string, crypto.Signer, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	return "", key, err
}

func (m *mockCryptoEngine) ImportRSAPrivateKey(key *rsa.PrivateKey) (string, crypto.Signer, error) {
	return "", key, nil
}

func (m *mockCryptoEngine) ImportECDSAPrivateKey(key *ecdsa.PrivateKey) (string, crypto.Signer, error) {
	return "", key, nil
}

func (m *mockCryptoEngine) ImportMLDSAPrivateKey(key crypto.Signer) (string, crypto.Signer, error) {
	return "", key, nil
}

func (m *mockCryptoEngine) ImportEd25519PrivateKey(key ed25519.PrivateKey) (string, crypto.Signer, error) {
	return "", key, nil
}

func (m *mockCryptoEngine) DeleteKey(keyID string) error {
	return nil
}

func (m *mockCryptoEngine) RenameKey(keyID string, newKeyID string) error {
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
