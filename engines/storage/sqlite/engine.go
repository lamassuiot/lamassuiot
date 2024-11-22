//go:build experimental
// +build experimental

package sqlite

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/v3/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/engines/storage"
	lconfig "github.com/lamassuiot/lamassuiot/v3/engines/storage/sqlite/config"
	log "github.com/sirupsen/logrus"
)

func Register() {
	storage.RegisterStorageEngine(config.SQLite, func(logger *log.Entry, conf config.PluggableStorageEngine) (storage.StorageEngine, error) {
		config, err := config.DecodeStruct[lconfig.SQLitePSEConfig](conf.Config)
		if err != nil {
			return nil, fmt.Errorf("could not decode couchdb config: %s", err)
		}
		return NewStorageEngine(logger, config)
	})
}

const (
	CA_DB_NAME     = "ca"
	DEVICE_DB_NAME = "devicemanager"
	DMS_DB_NAME    = "dmsmanager"
	ALERTS_DB_NAME = "alerts"
)

type SQLiteStorageEngine struct {
	storage.CommonStorageEngine
	Config lconfig.SQLitePSEConfig
	logger *log.Entry
}

func NewStorageEngine(logger *log.Entry, config lconfig.SQLitePSEConfig) (storage.StorageEngine, error) {
	return &SQLiteStorageEngine{
		Config: config,
		logger: logger,
	}, nil
}

func (s *SQLiteStorageEngine) GetProvider() config.StorageProvider {
	return config.SQLite
}

func (s *SQLiteStorageEngine) GetCAStorage() (storage.CACertificatesRepo, error) {
	if s.CA == nil {
		err := s.initialiceCACertStorage()
		if err != nil {
			return nil, fmt.Errorf("could not initialize sqlite CA and Cert clients: %s", err)
		}
	}

	return s.CA, nil
}

func (s *SQLiteStorageEngine) initialiceCACertStorage() error {
	psqlCli, err := CreateDBConnection(s.logger, s.Config, CA_DB_NAME)
	if err != nil {
		return err
	}

	if s.CA == nil {
		s.CA, err = NewCARepository(psqlCli)
		if err != nil {
			return err
		}
	}

	if s.Cert == nil {
		s.Cert, err = NewCertificateRepository(psqlCli)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLiteStorageEngine) GetCertstorage() (storage.CertificatesRepo, error) {
	if s.Cert == nil {
		err := s.initialiceCACertStorage()
		if err != nil {
			return nil, fmt.Errorf("could not initialize sqlite CA and Cert clients: %s", err)
		}
	}

	return s.Cert, nil
}

func (s *SQLiteStorageEngine) GetDeviceStorage() (storage.DeviceManagerRepo, error) {

	if s.Device == nil {
		psqlCli, err := CreateDBConnection(s.logger, s.Config, DEVICE_DB_NAME)
		if err != nil {
			return nil, fmt.Errorf("could not create sqlite client: %s", err)
		}

		deviceStore, err := NewDeviceManagerRepository(psqlCli)
		if err != nil {
			return nil, fmt.Errorf("could not initialize sqlite Device client: %s", err)
		}
		s.Device = deviceStore
	}
	return s.Device, nil
}

func (s *SQLiteStorageEngine) GetDMSStorage() (storage.DMSRepo, error) {
	if s.DMS == nil {
		psqlCli, err := CreateDBConnection(s.logger, s.Config, DMS_DB_NAME)
		if err != nil {
			return nil, fmt.Errorf("could not create sqlite client: %s", err)
		}

		dmsStore, err := NewDMSManagerRepository(psqlCli)
		if err != nil {
			return nil, fmt.Errorf("could not initialize sqlite DMS client: %s", err)
		}
		s.DMS = dmsStore
	}
	return s.DMS, nil
}

func (s *SQLiteStorageEngine) GetEnventsStorage() (storage.EventRepository, error) {
	if s.Events == nil {
		s.initialiceSubscriptionsStorage()
	}
	return s.Events, nil
}

func (s *SQLiteStorageEngine) GetSubscriptionsStorage() (storage.SubscriptionsRepository, error) {
	if s.Subscriptions == nil {
		s.initialiceSubscriptionsStorage()
	}
	return s.Subscriptions, nil
}

func (s *SQLiteStorageEngine) initialiceSubscriptionsStorage() error {
	psqlCli, err := CreateDBConnection(s.logger, s.Config, ALERTS_DB_NAME)
	if err != nil {
		return err
	}

	if s.Subscriptions == nil {
		s.Subscriptions, err = NewSubscriptionsSQLiteRepository(psqlCli)
		if err != nil {
			return err
		}
	}

	if s.Events == nil {
		s.Events, err = NewEventsSQLiteRepository(psqlCli)
		if err != nil {
			return err
		}
	}

	return nil
}
