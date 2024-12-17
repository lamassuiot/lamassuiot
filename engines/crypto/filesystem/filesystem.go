package filesystem

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/engines/crypto/software/v3"
	"github.com/sirupsen/logrus"
)

type FilesystemCryptoEngine struct {
	config           models.CryptoEngineInfo
	storageDirectory string
	logger           *logrus.Entry
}

func NewFilesystemPEMEngine(logger *logrus.Entry, conf config.CryptoEngineConfigAdapter[FilesystemEngineConfig]) (cryptoengines.CryptoEngine, error) {
	lGo := logger.WithField("subsystem-provider", "GoSoft")

	defaultMeta := map[string]interface{}{
		"lamassu.io/cryptoengine.golang.storage-path": conf,
	}

	err := checkAndCreateStorageDir(lGo, conf.Config.StorageDirectory)
	if err != nil {
		return nil, err
	}

	// Update KeyIDs in folder and remove old naming
	entries, err := os.ReadDir(conf.Config.StorageDirectory)
	if err != nil {
		return nil, err
	}

	lGo.Debugf("Starting key renaming to new format")
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		v1KeySuffix := "lms-caservice-certauth-keyid-"
		if strings.HasSuffix(v1KeySuffix, entry.Name()) {
			lGo.Debugf("Renaming key %s", entry.Name())
			newName := strings.Replace(entry.Name(), v1KeySuffix, "", 1)
			err := os.Rename(filepath.Join(conf.Config.StorageDirectory, entry.Name()), filepath.Join(conf.Config.StorageDirectory, newName))
			if err != nil {
				return nil, err
			}
		}
	}
	lGo.Debugf("Finished key renaming to new format")

	meta := helpers.MergeMaps[interface{}](&defaultMeta, &conf.Metadata)
	return &FilesystemCryptoEngine{
		logger:           lGo,
		storageDirectory: conf.Config.StorageDirectory,
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
	}, nil
}

func (engine *FilesystemCryptoEngine) GetEngineConfig() models.CryptoEngineInfo {
	return engine.config
}

func (engine *FilesystemCryptoEngine) GetPrivateKeyByID(keyID string) (crypto.Signer, error) {
	engine.logger.Debugf("reading %s Key", keyID)
	file := filepath.Join(engine.storageDirectory, keyID)

	pemBytes, err := os.ReadFile(file)
	if err != nil {
		engine.logger.Errorf("Could not read %s Key: %s", keyID, err)
		return nil, err
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no key found")
	}

	genericKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch genericKey.(type) {
	case *rsa.PrivateKey:
		return genericKey.(*rsa.PrivateKey), nil
	case *ecdsa.PrivateKey:
		return genericKey.(*ecdsa.PrivateKey), nil
	default:
		return nil, errors.New("unsupported key type")
	}
}

func (engine *FilesystemCryptoEngine) CreateRSAPrivateKey(keySize int) (string, crypto.Signer, error) {
	engine.logger.Debugf("creating RSA private key")

	_, key, err := software.NewSoftwareCryptoEngine(engine.logger).CreateRSAPrivateKey(keySize)
	if err != nil {
		engine.logger.Errorf("could not create RSA private key: %s", err)
		return "", nil, err
	}

	engine.logger.Debugf("RSA key successfully generated")
	return engine.importKey(key)
}

func (engine *FilesystemCryptoEngine) CreateECDSAPrivateKey(curve elliptic.Curve) (string, crypto.Signer, error) {
	engine.logger.Debugf("creating ECDSA private key")

	_, key, err := software.NewSoftwareCryptoEngine(engine.logger).CreateECDSAPrivateKey(curve)
	if err != nil {
		engine.logger.Errorf("could not create ECDSA private key: %s", err)
		return "", nil, err
	}

	engine.logger.Debugf("ECDSA key successfully generated")
	return engine.importKey(key)
}

func (engine *FilesystemCryptoEngine) DeleteKey(keyID string) error {
	return os.Remove(engine.storageDirectory + "/" + keyID)
}

func (engine *FilesystemCryptoEngine) ImportRSAPrivateKey(key *rsa.PrivateKey) (string, crypto.Signer, error) {
	engine.logger.Debugf("importing RSA private key")

	keyID, signer, err := engine.importKey(key)
	if err != nil {
		engine.logger.Errorf("could not import RSA key: %s", err)
		return "", nil, err
	}

	engine.logger.Debugf("RSA key successfully imported")
	return keyID, signer, nil
}

func (engine *FilesystemCryptoEngine) ImportECDSAPrivateKey(key *ecdsa.PrivateKey) (string, crypto.Signer, error) {
	engine.logger.Debugf("importing ECDSA private key")

	keyID, signer, err := engine.importKey(key)
	if err != nil {
		engine.logger.Errorf("could not import ECDSA key: %s", err)
		return "", nil, err
	}

	engine.logger.Debugf("ECDSA key successfully imported")
	return keyID, signer, nil
}

func (engine *FilesystemCryptoEngine) importKey(key interface{}) (string, crypto.Signer, error) {
	var pubKey any
	switch k := key.(type) {
	case *rsa.PrivateKey:
		pubKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		pubKey = &k.PublicKey
	default:
		return "", nil, errors.New("unsupported key type")
	}

	softEngine := software.NewSoftwareCryptoEngine(engine.logger)
	keyID, err := softEngine.EncodePKIXPublicKeyDigest(pubKey)
	if err != nil {
		engine.logger.Errorf("could not encode public key digest: %s", err)
		return "", nil, err
	}

	b64PemKey, err := softEngine.MarshalAndEncodePKIXPrivateKey(key)
	if err != nil {
		engine.logger.Errorf("could not marshal and encode private key: %s", err)
		return "", nil, err
	}

	pemKey, err := base64.StdEncoding.DecodeString(b64PemKey)
	if err != nil {
		engine.logger.Errorf("could not decode RSA private key: %s", err)
		return "", nil, err
	}

	file := filepath.Join(engine.storageDirectory, keyID)
	err = os.WriteFile(file, pemKey, 0600)
	if err != nil {
		engine.logger.Errorf("could not store RSA private key: %s", err)
		return "", nil, err
	}

	signer, err := engine.GetPrivateKeyByID(keyID)
	if err != nil {
		engine.logger.Errorf("could not get private key by ID: %s", err)
		return "", nil, err
	}

	return keyID, signer, nil
}

func checkAndCreateStorageDir(logger *logrus.Entry, dir string) error {
	var err error
	if _, err = os.Stat(dir); os.IsNotExist(err) {
		logger.Warnf("storage directory %s does not exist. Will create such directory", dir)
		err = os.MkdirAll(dir, 0750)
		if err != nil {
			logger.Errorf("something went wrong while creating storage path: %s", err)
		}
		return err
	} else if err != nil {
		logger.Errorf("something went wrong while checking storage: %s", err)
		return err
	}

	return nil
}
