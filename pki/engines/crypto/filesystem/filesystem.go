package filesystem

import (
	"context"
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
	"github.com/lamassuiot/lamassuiot/pki/v3/engines/crypto/software"
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

	meta := helpers.MergeMaps(&defaultMeta, &conf.Metadata)
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
						7680,
						15360,
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

func (engine *FilesystemCryptoEngine) GetPrivateKeyByID(ctx context.Context, keyID string) (crypto.Signer, error) {
	lFunc := helpers.ConfigureLogger(ctx, engine.logger)
	lFunc.Debugf("reading %s Key", keyID)
	file := filepath.Join(engine.storageDirectory, keyID)

	pemBytes, err := os.ReadFile(file)
	if err != nil {
		lFunc.Errorf("Could not read %s Key: %s", keyID, err)
		return nil, err
	}

	return engine.softCryptoEngine.ParsePrivateKey(pemBytes)
}

func (engine *FilesystemCryptoEngine) ListPrivateKeyIDs(ctx context.Context) ([]string, error) {
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

func (engine *FilesystemCryptoEngine) RenameKey(ctx context.Context, oldID, newID string) error {
	lFunc := helpers.ConfigureLogger(ctx, engine.logger)
	lFunc.Debugf("renaming key %s to %s", oldID, newID)
	err := os.Rename(filepath.Join(engine.storageDirectory, oldID), filepath.Join(engine.storageDirectory, newID))
	if err != nil {
		lFunc.Errorf("could not rename key %s to %s: %s", oldID, newID, err)
		return err
	}

	lFunc.Debugf("key %s successfully renamed to %s", oldID, newID)
	return nil
}

func (engine *FilesystemCryptoEngine) CreateRSAPrivateKey(ctx context.Context, keySize int) (string, crypto.Signer, error) {
	lFunc := helpers.ConfigureLogger(ctx, engine.logger)
	lFunc.Debugf("creating RSA private key")

	_, key, err := engine.softCryptoEngine.CreateRSAPrivateKey(ctx, keySize)
	if err != nil {
		lFunc.Errorf("could not create RSA private key: %s", err)
		return "", nil, err
	}

	lFunc.Debugf("RSA key successfully generated")
	return engine.importKey(ctx, key)
}

func (engine *FilesystemCryptoEngine) CreateECDSAPrivateKey(ctx context.Context, curve elliptic.Curve) (string, crypto.Signer, error) {
	lFunc := helpers.ConfigureLogger(ctx, engine.logger)
	lFunc.Debugf("creating ECDSA private key")

	_, key, err := engine.softCryptoEngine.CreateECDSAPrivateKey(ctx, curve)
	if err != nil {
		lFunc.Errorf("could not create ECDSA private key: %s", err)
		return "", nil, err
	}

	lFunc.Debugf("ECDSA key successfully generated")
	return engine.importKey(ctx, key)
}

func (engine *FilesystemCryptoEngine) DeleteKey(ctx context.Context, keyID string) error {
	return os.Remove(engine.storageDirectory + "/" + keyID)
}

func (engine *FilesystemCryptoEngine) ImportRSAPrivateKey(ctx context.Context, key *rsa.PrivateKey) (string, crypto.Signer, error) {
	lFunc := helpers.ConfigureLogger(ctx, engine.logger)
	lFunc.Debugf("importing RSA private key")

	keyID, signer, err := engine.importKey(ctx, key)
	if err != nil {
		lFunc.Errorf("could not import RSA key: %s", err)
		return "", nil, err
	}

	lFunc.Debugf("RSA key successfully imported")
	return keyID, signer, nil
}

func (engine *FilesystemCryptoEngine) ImportECDSAPrivateKey(ctx context.Context, key *ecdsa.PrivateKey) (string, crypto.Signer, error) {
	lFunc := helpers.ConfigureLogger(ctx, engine.logger)
	lFunc.Debugf("importing ECDSA private key")

	keyID, signer, err := engine.importKey(ctx, key)
	if err != nil {
		lFunc.Errorf("could not import ECDSA key: %s", err)
		return "", nil, err
	}

	lFunc.Debugf("ECDSA key successfully imported")
	return keyID, signer, nil
}

func (engine *FilesystemCryptoEngine) importKey(ctx context.Context, key interface{}) (string, crypto.Signer, error) {
	lFunc := helpers.ConfigureLogger(ctx, engine.logger)
	pubKey := key.(crypto.Signer).Public()

	keyID, err := engine.softCryptoEngine.EncodePKIXPublicKeyDigest(ctx, pubKey)
	if err != nil {
		lFunc.Errorf("could not encode public key digest: %s", err)
		return "", nil, err
	}

	b64PemKey, err := engine.softCryptoEngine.MarshalAndEncodePKIXPrivateKey(ctx, key)
	if err != nil {
		lFunc.Errorf("could not marshal and encode private key: %s", err)
		return "", nil, err
	}

	pemKey, err := base64.StdEncoding.DecodeString(b64PemKey)
	if err != nil {
		lFunc.Errorf("could not decode RSA private key: %s", err)
		return "", nil, err
	}

	file := filepath.Join(engine.storageDirectory, keyID)
	err = os.WriteFile(file, pemKey, 0600)
	if err != nil {
		lFunc.Errorf("could not store RSA private key: %s", err)
		return "", nil, err
	}

	signer, err := engine.GetPrivateKeyByID(ctx, keyID)
	if err != nil {
		lFunc.Errorf("could not get private key by ID: %s", err)
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
