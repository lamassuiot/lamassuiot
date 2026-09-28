package filesystem

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
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
	softCryptoEngine *software.SoftwareCryptoEngine
	config           models.CryptoEngineInfo
	storageDirectory string
	storageRoot      *os.Root
	tenantID         string
	logger           *logrus.Entry
}

func NewFilesystemPEMEngine(logger *logrus.Entry, conf config.CryptoEngineConfigAdapter[FilesystemEngineConfig]) (cryptoengines.CryptoEngine, error) {
	lGo := logger.WithField("subsystem-provider", "GoSoft")

	defaultMeta := map[string]interface{}{
		"lamassu.io/cryptoengine.golang.storage-path": conf,
	}

	storageDirectory := conf.Config.StorageDirectory
	if conf.TenantID != "" {
		if !isSafePathComponent(conf.TenantID) {
			return nil, fmt.Errorf("invalid tenant ID for filesystem crypto engine")
		}
		storageDirectory = filepath.Join(storageDirectory, "tenants", conf.TenantID)
	}
	err := checkAndCreateStorageDir(lGo, storageDirectory)
	if err != nil {
		return nil, err
	}
	storageRoot, err := os.OpenRoot(storageDirectory)
	if err != nil {
		return nil, fmt.Errorf("could not open filesystem crypto storage root: %w", err)
	}
	if conf.TenantID != "" {
		if err := storageRoot.Chmod(".", 0700); err != nil {
			_ = storageRoot.Close()
			return nil, fmt.Errorf("could not restrict tenant crypto storage root: %w", err)
		}
	}

	meta := helpers.MergeMaps(&defaultMeta, &conf.Metadata)
	return &FilesystemCryptoEngine{
		logger:           lGo,
		softCryptoEngine: software.NewSoftwareCryptoEngine(lGo),
		storageDirectory: storageDirectory,
		storageRoot:      storageRoot,
		tenantID:         conf.TenantID,
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

func (engine *FilesystemCryptoEngine) Close() error {
	return engine.storageRoot.Close()
}

func (engine *FilesystemCryptoEngine) GetPrivateKeyByID(keyID string) (crypto.Signer, error) {
	engine.logger.Debugf("reading %s Key", keyID)
	file, err := engine.keyPath(keyID)
	if err != nil {
		return nil, err
	}
	keyFile, err := engine.storageRoot.Open(file)
	if err != nil {
		engine.logger.Errorf("Could not read %s Key: %s", keyID, err)
		return nil, err
	}
	defer keyFile.Close()

	info, err := keyFile.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("key path is not a regular file")
	}

	pemBytes, err := io.ReadAll(keyFile)
	if err != nil {
		engine.logger.Errorf("Could not read %s Key: %s", keyID, err)
		return nil, err
	}

	return engine.softCryptoEngine.ParsePrivateKey(pemBytes)
}

func (engine *FilesystemCryptoEngine) ListPrivateKeyIDs() ([]string, error) {
	// Update KeyIDs in folder and remove old naming
	entries, err := fs.ReadDir(engine.storageRoot.FS(), ".")
	if err != nil {
		return nil, err
	}

	var keyIDs []string
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			continue
		}

		keyIDs = append(keyIDs, entry.Name())
	}

	return keyIDs, nil
}

func (engine *FilesystemCryptoEngine) RenameKey(oldID, newID string) error {
	engine.logger.Debugf("renaming key %s to %s", oldID, newID)
	oldPath, err := engine.keyPath(oldID)
	if err != nil {
		return err
	}
	oldInfo, err := engine.storageRoot.Lstat(oldPath)
	if err != nil {
		return err
	}
	if !oldInfo.Mode().IsRegular() {
		return fmt.Errorf("source key path is not a regular file")
	}
	newPath, err := engine.keyPath(newID)
	if err != nil {
		return err
	}
	err = engine.storageRoot.Link(oldPath, newPath)
	if err != nil {
		engine.logger.Errorf("could not rename key %s to %s: %s", oldID, newID, err)
		return err
	}
	if err = engine.storageRoot.Remove(oldPath); err != nil {
		_ = engine.storageRoot.Remove(newPath)
	}
	if err != nil {
		engine.logger.Errorf("could not rename key %s to %s: %s", oldID, newID, err)
		return err
	}

	engine.logger.Debugf("key %s successfully renamed to %s", oldID, newID)
	return nil
}

func (engine *FilesystemCryptoEngine) CreateRSAPrivateKey(ctx context.Context, keySize int) (string, crypto.Signer, error) {
	engine.logger.Debugf("creating RSA private key")

	_, key, err := engine.softCryptoEngine.CreateRSAPrivateKey(ctx, keySize)
	if err != nil {
		engine.logger.Errorf("could not create RSA private key: %s", err)
		return "", nil, err
	}

	engine.logger.Debugf("RSA key successfully generated")
	return engine.importKey(key)
}

func (engine *FilesystemCryptoEngine) CreateECDSAPrivateKey(ctx context.Context, curve elliptic.Curve) (string, crypto.Signer, error) {
	engine.logger.Debugf("creating ECDSA private key")

	_, key, err := engine.softCryptoEngine.CreateECDSAPrivateKey(ctx, curve)
	if err != nil {
		engine.logger.Errorf("could not create ECDSA private key: %s", err)
		return "", nil, err
	}

	engine.logger.Debugf("ECDSA key successfully generated")
	return engine.importKey(key)
}

func (engine *FilesystemCryptoEngine) DeleteKey(keyID string) error {
	file, err := engine.keyPath(keyID)
	if err != nil {
		return err
	}
	return engine.storageRoot.Remove(file)
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

	file, err := engine.keyPath(keyID)
	if err != nil {
		return "", nil, err
	}
	keyFile, err := engine.storageRoot.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		engine.logger.Errorf("could not store RSA private key: %s", err)
		return "", nil, err
	}
	if _, err = keyFile.Write(pemKey); err != nil {
		_ = keyFile.Close()
		_ = engine.storageRoot.Remove(file)
		return "", nil, err
	}
	if err = keyFile.Close(); err != nil {
		_ = engine.storageRoot.Remove(file)
		return "", nil, err
	}

	signer, err := engine.GetPrivateKeyByID(keyID)
	if err != nil {
		engine.logger.Errorf("could not get private key by ID: %s", err)
		return "", nil, err
	}

	return keyID, signer, nil
}

func (engine *FilesystemCryptoEngine) keyPath(keyID string) (string, error) {
	if !isSafePathComponent(keyID) {
		return "", fmt.Errorf("invalid key ID")
	}
	return keyID, nil
}

func isSafePathComponent(value string) bool {
	if value == "" || value == "." || value == ".." {
		return false
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') &&
			(char < 'A' || char > 'Z') &&
			(char < '0' || char > '9') &&
			char != '-' && char != '_' {
			return false
		}
	}
	return true
}

func checkAndCreateStorageDir(logger *logrus.Entry, dir string) error {
	absolutePath, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	volume := filepath.VolumeName(absolutePath)
	current := volume + string(os.PathSeparator)
	relative := strings.TrimPrefix(absolutePath, current)
	for _, component := range strings.Split(relative, string(os.PathSeparator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if err := os.Mkdir(current, 0750); err != nil {
				logger.Errorf("something went wrong while creating storage path: %s", err)
				return err
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("filesystem crypto storage path must contain only real directories")
		}
	}
	return nil
}
