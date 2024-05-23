package postgres

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage"
	log "github.com/sirupsen/logrus"
)

func init() {
	storage.RegisterStorageEngine(config.Postgres, func(logger *log.Entry, conf config.PluggableStorageEngine) (storage.StorageEngine, error) {
		return NewStorageEngine(logger, conf.Postgres)
	})
}

const (
	CA_DB_NAME     = "ca"
	DEVICE_DB_NAME = "devicemanager"
	DMS_DB_NAME    = "dmsmanager"
	ALERTS_DB_NAME = "alerts"
)

type PostgresStorageEngine struct {
	storage.CommonStorageEngine
	Config config.PostgresPSEConfig
	logger *log.Entry
}

func NewStorageEngine(logger *log.Entry, config config.PostgresPSEConfig) (storage.StorageEngine, error) {
	return &PostgresStorageEngine{
		Config: config,
		logger: logger,
	}, nil
}

func (s *PostgresStorageEngine) GetCAStorage() (storage.CACertificatesRepo, error) {
	if s.CA == nil {
		err := s.initialiceCACertStorage()
		if err != nil {
			return nil, fmt.Errorf("could not initialize postgres CA and Cert clients: %s", err)
		}
	}

	return s.CA, nil
}

func (s *PostgresStorageEngine) initialiceCACertStorage() error {
	psqlCli, err := CreatePostgresDBConnection(s.logger, s.Config, CA_DB_NAME)
	if err != nil {
		return err
	}

	if s.CA == nil {
		s.CA, err = NewCAPostgresRepository(psqlCli)
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

func (s *PostgresStorageEngine) GetCertstorage() (storage.CertificatesRepo, error) {
	if s.Cert == nil {
		err := s.initialiceCACertStorage()
		if err != nil {
			return nil, fmt.Errorf("could not initialize postgres CA and Cert clients: %s", err)
		}
	}

	return s.Cert, nil
}

func (s *PostgresStorageEngine) GetDeviceStorage() (storage.DeviceManagerRepo, error) {

	if s.Device == nil {
		psqlCli, err := CreatePostgresDBConnection(s.logger, s.Config, DEVICE_DB_NAME)
		if err != nil {
			return nil, fmt.Errorf("could not create postgres client: %s", err)
		}

		deviceStore, err := NewDeviceManagerRepository(psqlCli)
		if err != nil {
			return nil, fmt.Errorf("could not initialize postgres Device client: %s", err)
		}
		s.Device = deviceStore
	}
	return s.Device, nil
}

func (s *PostgresStorageEngine) GetDMSStorage() (storage.DMSRepo, error) {
	if s.DMS == nil {
		psqlCli, err := CreatePostgresDBConnection(s.logger, s.Config, DMS_DB_NAME)
		if err != nil {
			return nil, fmt.Errorf("could not create postgres client: %s", err)
		}

		dmsStore, err := NewDMSManagerRepository(psqlCli)
		if err != nil {
			return nil, fmt.Errorf("could not initialize postgres DMS client: %s", err)
		}
		s.DMS = dmsStore
	}
	return s.DMS, nil
}

func (s *PostgresStorageEngine) GetEnventsStorage() (storage.EventRepository, error) {
	if s.Events == nil {
		s.initialiceSubscriptionsStorage()
	}
	return s.Events, nil
}

func (s *PostgresStorageEngine) GetSubscriptionsStorage() (storage.SubscriptionsRepository, error) {
	if s.Subscriptions == nil {
		s.initialiceSubscriptionsStorage()
	}
	return s.Subscriptions, nil
}

func (s *PostgresStorageEngine) initialiceSubscriptionsStorage() error {
	psqlCli, err := CreatePostgresDBConnection(s.logger, s.Config, ALERTS_DB_NAME)
	if err != nil {
		return err
	}

	if s.Subscriptions == nil {
		s.Subscriptions, err = NewSubscriptionsPostgresRepository(psqlCli)
		if err != nil {
			return err
		}
	}

	if s.Events == nil {
		s.Events, err = NewEventsPostgresRepository(psqlCli)
		if err != nil {
			return err
		}
	}

	return nil
}
