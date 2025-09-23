package filesystem

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/engines/crypto/software/v3"
	"github.com/sirupsen/logrus"
)

type FilesystemCryptoEngine struct {
	softCryptoEngine *software.SoftwareCryptoEngine
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

	meta := helpers.MergeMaps[interface{}](&defaultMeta, &conf.Metadata)
	return &FilesystemCryptoEngine{
		logger:           lGo,
		softCryptoEngine: software.NewSoftwareCryptoEngine(lGo),
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
				{
					Type: models.KeyType(x509.MLDSA),
					Sizes: []int{
						44,
						65,
						87,
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

	return engine.softCryptoEngine.ParsePrivateKey(pemBytes)
}

func (engine *FilesystemCryptoEngine) ListPrivateKeyIDs() ([]string, error) {
	// Update KeyIDs in folder and remove old naming
	entries, err := os.ReadDir(engine.storageDirectory)
	if err != nil {
		return nil, err
	}

	var keyIDs []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		keyIDs = append(keyIDs, entry.Name())
	}

	return keyIDs, nil
}

func (engine *FilesystemCryptoEngine) RenameKey(oldID, newID string) error {
	engine.logger.Debugf("renaming key %s to %s", oldID, newID)
	err := os.Rename(filepath.Join(engine.storageDirectory, oldID), filepath.Join(engine.storageDirectory, newID))
	if err != nil {
		engine.logger.Errorf("could not rename key %s to %s: %s", oldID, newID, err)
		return err
	}

	engine.logger.Debugf("key %s successfully renamed to %s", oldID, newID)
	return nil
}

func (engine *FilesystemCryptoEngine) CreateRSAPrivateKey(keySize int) (string, crypto.Signer, error) {
	engine.logger.Debugf("creating RSA private key")

	_, key, err := engine.softCryptoEngine.CreateRSAPrivateKey(keySize)
	if err != nil {
		engine.logger.Errorf("could not create RSA private key: %s", err)
		return "", nil, err
	}

	engine.logger.Debugf("RSA key successfully generated")
	return engine.importKey(key)
}

func (engine *FilesystemCryptoEngine) CreateECDSAPrivateKey(curve elliptic.Curve) (string, crypto.Signer, error) {
	engine.logger.Debugf("creating ECDSA private key")

	_, key, err := engine.softCryptoEngine.CreateECDSAPrivateKey(curve)
	if err != nil {
		engine.logger.Errorf("could not create ECDSA private key: %s", err)
		return "", nil, err
	}

	engine.logger.Debugf("ECDSA key successfully generated")
	return engine.importKey(key)
}

func (engine *FilesystemCryptoEngine) CreateMLDSAPrivateKey(dimensions int) (string, crypto.Signer, error) {
	engine.logger.Debugf("creating ML-DSA-%v private key", dimensions)

	_, key, err := engine.softCryptoEngine.CreateMLDSAPrivateKey(dimensions)
	if err != nil {
		engine.logger.Errorf("could not create ML-DSA-%v private key: %s", dimensions, err)
		return "", nil, err
	}

	engine.logger.Debugf("ML-DSA-%q key successfully generated", dimensions)
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

func (engine *FilesystemCryptoEngine) ImportMLDSAPrivateKey(key crypto.Signer) (string, crypto.Signer, error) {
	engine.logger.Debugf("importing MLDSA private key")

	keyID, signer, err := engine.importKey(key)
	if err != nil {
		engine.logger.Errorf("could not import MLDSA key: %s", err)
		return "", nil, err
	}

	engine.logger.Debugf("MLDSA key successfully imported")
	return keyID, signer, nil
}

func (engine *FilesystemCryptoEngine) importKey(key interface{}) (string, crypto.Signer, error) {
	pubKey := key.(crypto.Signer).Public()

	keyID, err := engine.softCryptoEngine.EncodePKIXPublicKeyDigest(pubKey)
	if err != nil {
		engine.logger.Errorf("could not encode public key digest: %s", err)
		return "", nil, err
	}

	b64PemKey, err := engine.softCryptoEngine.MarshalAndEncodePKIXPrivateKey(key)
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
