package cryptoengines

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"runtime"

	keystorager "github.com/lamassuiot/lamassuiot/v2/pkg/cryptoengines/key_storager"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/sirupsen/logrus"
)

type GoCryptoEngine struct {
	config  models.CryptoEngineInfo
	keyRepo keystorager.KeyStorager
	logger  *logrus.Entry
}

func NewGolangPEMEngine(logger *logrus.Entry, storage keystorager.KeyStorager) CryptoEngine {
	log := logger.WithField("subsystem-provider", "GoSoft")
	return &GoCryptoEngine{
		logger:  log,
		keyRepo: storage,
		config: models.CryptoEngineInfo{
			Type:          models.Golang,
			SecurityLevel: models.SL0,
			Provider:      "Golang",
			Name:          runtime.Version(),
			Metadata:      map[string]any{},
			SupportedKeyTypes: []models.SupportedKeyTypeInfo{
				{
					Type: models.KeyType(x509.RSA),
					Sizes: []int{
						1024,
						2048,
						3072,
						4096,
					},
				},
				{
					Type: models.KeyType(x509.ECDSA),
					Sizes: []int{
						224,
						256,
						384,
						521,
					},
				},
			},
		},
	}
}

func (engine *GoCryptoEngine) GetEngineConfig() models.CryptoEngineInfo {
	return engine.config
}

func (engine *GoCryptoEngine) GetPrivateKeyByID(keyID string) (crypto.Signer, error) {
	engine.logger.Debugf("reading %s Key", keyID)
	keyBytes, err := engine.keyRepo.Get(keyID)
	if err != nil {
		engine.logger.Errorf("could not parse RSA PKCS1 %s key", keyID)
		return nil, err
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		engine.logger.Errorf("could not decode %s PEM Key. Block is nil", keyID)
		return nil, fmt.Errorf("failed to parse PEM block containing the key")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		engine.logger.Debugf("key %s is RSA in PKCS1 encoding format", keyID)
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			engine.logger.Errorf("could not parse RSA PKCS1 %s key", keyID)
			return nil, err
		}
		engine.logger.Debugf("successfully decoded PKCS1 %s key", keyID)
		return key, err
	case "EC PRIVATE KEY":
		engine.logger.Debugf("Key %s is EC", keyID)
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			engine.logger.Errorf("could not parse EC %s key", keyID)
			return nil, err
		}
		engine.logger.Debugf("successfully decoded EC %s key", keyID)
		return key, err
	default:
		engine.logger.Errorf("could not parse key %s in PEM '%s' format", keyID, block.Type)
		return nil, fmt.Errorf("unsupported key type")
	}
}

func (engine *GoCryptoEngine) CreateRSAPrivateKey(keySize int, keyID string) (crypto.Signer, error) {
	engine.logger.Debugf("creating RSA %d key for keyID: %s", keySize, keyID)
	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		engine.logger.Errorf("could not create %s RSA key: %s", keyID, err)
		return nil, err
	}

	return engine.ImportRSAPrivateKey(key, keyID)
}

func (engine *GoCryptoEngine) CreateECDSAPrivateKey(curve elliptic.Curve, keyID string) (crypto.Signer, error) {
	engine.logger.Debugf("creating ECDSA %d key for keyID: %s", curve.Params().BitSize, keyID)
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		engine.logger.Errorf("could not create %s ECDSA key: %s", keyID, err)
		return nil, err
	}

	return engine.ImportECDSAPrivateKey(key, keyID)
}

func (engine *GoCryptoEngine) DeleteKey(keyID string) error {
	return engine.keyRepo.Delete(keyID)
}

func (engine *GoCryptoEngine) ImportRSAPrivateKey(key *rsa.PrivateKey, keyID string) (crypto.Signer, error) {
	engine.logger.Debugf("importing RSA %d key for keyID: %s", key.Size(), keyID)
	return engine.importPrivateKey(key, keyID)
}

func (engine *GoCryptoEngine) ImportECDSAPrivateKey(key *ecdsa.PrivateKey, keyID string) (crypto.Signer, error) {
	engine.logger.Debugf("importing ECDSA %d key for keyID: %s", key.Params().BitSize, keyID)
	return engine.importPrivateKey(key, keyID)
}

func (engine *GoCryptoEngine) importPrivateKey(key any, keyID string) (crypto.Signer, error) {
	pkcs8KeyDer, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		engine.logger.Errorf("could not marshal %s key into PKCS8 DER: %s", keyID, err)
		return nil, err
	}

	pkcs8KeyPem := pem.EncodeToMemory(&pem.Block{
		Bytes: pkcs8KeyDer,
		Type:  "PRIVATE KEY",
	})

	err = engine.keyRepo.Create(keyID, pkcs8KeyPem)
	if err != nil {
		engine.logger.Errorf("could not save %s key: %s", keyID, err)
		return nil, err
	}

	return engine.GetPrivateKeyByID(keyID)
}
