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
	"io/ioutil"
	"os"
	"runtime"

	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/sirupsen/logrus"
)

var lGo *logrus.Entry

type GoCryptoEngine struct {
	config           models.CryptoEngineInfo
	storageDirectory string
}

func NewGolangPEMEngine(logger *logrus.Entry, conf config.GolangEngineConfig) CryptoEngine {
	lGo = logger.WithField("subsystem-provider", "GoSoft")

	defaultMeta := map[string]interface{}{
		"lamassu.io/cryptoengine.golang.storage-path": conf.StorageDirectory,
	}
	meta := helpers.MergeMaps[interface{}](&defaultMeta, &conf.Metadata)
	return &GoCryptoEngine{
		storageDirectory: conf.StorageDirectory,
		config: models.CryptoEngineInfo{
			Type:          models.Golang,
			SecurityLevel: models.SL0,
			Provider:      "Golang",
			Name:          runtime.Version(),
			Metadata:      *meta,
			SupportedKeyTypes: []models.SupportedKeyTypeInfo{
				{
					Type: models.KeyType(x509.RSA),
					Sizes: []int{
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
						512,
					},
				},
			},
		},
	}
}

func (p *GoCryptoEngine) GetEngineConfig() models.CryptoEngineInfo {
	return p.config
}

func (p *GoCryptoEngine) GetPrivateKeyByID(keyID string) (crypto.Signer, error) {
	lGo.Debugf("reading %s Key", keyID)
	privatePEM, err := ioutil.ReadFile(p.storageDirectory + "/" + keyID)
	if err != nil {
		lGo.Errorf("Could not read %s Key: %s", keyID, err)
		return nil, err
	}

	block, _ := pem.Decode(privatePEM)
	if block == nil {
		lGo.Errorf("could not decode %s PEM Key. Block is nil", keyID)
		return nil, fmt.Errorf("failed to parse PEM block containing the key")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		lGo.Debugf("key %s is RSA in PKCS1 encoding format", keyID)
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			lGo.Errorf("could not parse RSA PKCS1 %s key", keyID)
			return nil, err
		}
		lGo.Debugf("successfully decoded PKCS1 %s key", keyID)
		return key, err
	case "EC PRIVATE KEY":
		lGo.Debugf("Key %s is EC", keyID)
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			lGo.Errorf("could not parse EC %s key", keyID)
			return nil, err
		}
		lGo.Debugf("successfully decoded EC %s key", keyID)
		return key, err
	default:
		lGo.Errorf("could not parse key %s in PEM '%s' format", keyID, block.Type)
		return nil, fmt.Errorf("unsupported key type")
	}
}

func (p *GoCryptoEngine) CreateRSAPrivateKey(keySize int, keyID string) (crypto.Signer, error) {
	lGo.Debugf("creating RSA %d key for keyID: %s", keySize, keyID)
	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		lGo.Errorf("could not create %s RSA key: %s", keyID, err)
		return nil, err
	}

	return p.ImportRSAPrivateKey(key, keyID)
}

func (p *GoCryptoEngine) CreateECDSAPrivateKey(curve elliptic.Curve, keyID string) (crypto.Signer, error) {
	lGo.Debugf("creating ECDSA %d key for keyID: %s", curve.Params().BitSize, keyID)
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		lGo.Errorf("could not create %s ECDSA key: %s", keyID, err)
		return nil, err
	}

	return p.ImportECDSAPrivateKey(key, keyID)
}

func (p *GoCryptoEngine) DeleteKey(keyID string) error {
	return os.Remove(p.storageDirectory + "/" + keyID)
}

func (p *GoCryptoEngine) ImportRSAPrivateKey(key *rsa.PrivateKey, keyID string) (crypto.Signer, error) {
	p.checkAndCreateStorageDir()

	err := ioutil.WriteFile(p.storageDirectory+"/"+keyID, pem.EncodeToMemory(&pem.Block{
		Bytes: x509.MarshalPKCS1PrivateKey(key),
		Type:  "RSA PRIVATE KEY",
	}), 0644)
	if err != nil {
		lGo.Errorf("could not save %s RSA key: %s", keyID, err)
		return nil, err
	}

	return p.GetPrivateKeyByID(keyID)
}

func (p *GoCryptoEngine) ImportECDSAPrivateKey(key *ecdsa.PrivateKey, keyID string) (crypto.Signer, error) {
	p.checkAndCreateStorageDir()

	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}

	err = ioutil.WriteFile(p.storageDirectory+"/"+keyID, pem.EncodeToMemory(&pem.Block{
		Bytes: b,
		Type:  "EC PRIVATE KEY",
	}), 0644)
	if err != nil {
		lGo.Errorf("could not save %s ECDSA key: %s", keyID, err)
		return nil, err
	}

	return p.GetPrivateKeyByID(keyID)
}

func (p *GoCryptoEngine) checkAndCreateStorageDir() error {
	if _, err := os.Stat(p.storageDirectory); os.IsNotExist(err) {
		lGo.Warnf("storage directory %s does not exist. Will create such directory", p.storageDirectory)
		err = os.MkdirAll(p.storageDirectory, 0755)
		if err != nil {
			lGo.Errorf("something went wrong while creating storage path: %s", err)
		}
	} else {
		lGo.Errorf("something went wrong while checking storage: %s", err)
		return err
	}

	return nil
}
