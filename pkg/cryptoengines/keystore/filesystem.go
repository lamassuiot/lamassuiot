package keystore

import (
	"os"
	"path/filepath"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/sirupsen/logrus"
)

type FilesystemKeyStorage struct {
	logger    *logrus.Entry
	directory string
}

func NewFilesystemKeyStorage(logger *logrus.Entry, conf config.GolangFilesystemEngineConfig) KeyStore {
	return &FilesystemKeyStorage{
		logger:    logger,
		directory: conf.StorageDirectory,
	}
}

func (s *FilesystemKeyStorage) Get(keyID string) ([]byte, error) {
	s.logger.Debugf("reading %s Key", keyID)

	// Safely construct file path
	filePath := filepath.Join(s.directory, keyID)
	filePath = filepath.Clean(filePath)

	key, err := os.ReadFile(filePath)
	if err != nil {
		s.logger.Errorf("Could not read %s Key: %s", keyID, err)
		return nil, err
	}

	return key, nil
}

func (s *FilesystemKeyStorage) Create(keyID string, key []byte) error {
	err := s.checkAndCreateStorageDir()
	if err != nil {
		s.logger.Errorf("could not verify storage dir: %s", err)
		return err
	}

	// Safely construct file path
	filePath := filepath.Join(s.directory, keyID)
	filePath = filepath.Clean(filePath)

	err = os.WriteFile(filePath, key, 0600)
	if err != nil {
		s.logger.Errorf("could not save %s key: %s", keyID, err)
		return err
	}

	return nil
}

func (s *FilesystemKeyStorage) Delete(keyID string) error {
	// Safely construct file path
	filePath := filepath.Join(s.directory, keyID)
	filePath = filepath.Clean(filePath)

	return os.Remove(filePath)
}

func (s *FilesystemKeyStorage) checkAndCreateStorageDir() error {
	var err error
	if _, err = os.Stat(s.directory); os.IsNotExist(err) {
		s.logger.Warnf("storage directory %s does not exist. Will create such directory", s.directory)
		err = os.MkdirAll(s.directory, 0750)
		if err != nil {
			s.logger.Errorf("something went wrong while creating storage path: %s", err)
		}
		return err
	} else if err != nil {
		s.logger.Errorf("something went wrong while checking storage: %s", err)
		return err
	}

	return nil
}
