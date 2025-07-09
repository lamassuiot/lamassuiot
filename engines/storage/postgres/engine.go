package postgres

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	lconfig "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/config"
	log "github.com/sirupsen/logrus"
)

func Register() {
	storage.RegisterStorageEngine(config.Postgres, func(logger *log.Entry, conf config.PluggableStorageEngine) (storage.StorageEngine, error) {
		config, err := config.DecodeStruct[lconfig.PostgresPSEConfig](conf.Config)
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
	VA_DB_NAME     = "va"
	KMS_DB_NAME    = "kms"
)

type PostgresStorageEngine struct {
	storage.CommonStorageEngine
	Config lconfig.PostgresPSEConfig
	logger *log.Entry
}

func NewStorageEngine(logger *log.Entry, config lconfig.PostgresPSEConfig) (storage.StorageEngine, error) {
	return &PostgresStorageEngine{
		Config: config,
		logger: logger,
	}, nil
}

func (s *PostgresStorageEngine) GetProvider() config.StorageProvider {
	return config.Postgres
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

	m := NewMigrator(s.logger, psqlCli)
	m.MigrateToLatest()

	if s.CA == nil {
		s.CA, err = NewCAPostgresRepository(s.logger, psqlCli)
		if err != nil {
			return err
		}
	}

	if s.Cert == nil {
		s.Cert, err = NewCertificateRepository(s.logger, psqlCli)
		if err != nil {
			return err
		}
	}

	if s.CACertificateRequest == nil {
		s.CACertificateRequest, err = NewCACertRequestPostgresRepository(s.logger, psqlCli)
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

func (s *PostgresStorageEngine) GetCACertificateRequestStorage() (storage.CACertificateRequestRepo, error) {
	if s.CACertificateRequest == nil {
		err := s.initialiceCACertStorage()
		if err != nil {
			return nil, fmt.Errorf("could not initialize postgres CA request client: %s", err)
		}
	}
	return s.CACertificateRequest, nil
}

func (s *PostgresStorageEngine) GetDeviceStorage() (storage.DeviceManagerRepo, error) {
	if s.Device == nil {
		psqlCli, err := CreatePostgresDBConnection(s.logger, s.Config, DEVICE_DB_NAME)
		if err != nil {
			return nil, fmt.Errorf("could not create postgres client: %s", err)
		}

		m := NewMigrator(s.logger, psqlCli)
		m.MigrateToLatest()

		deviceStore, err := NewDeviceManagerRepository(s.logger, psqlCli)
		if err != nil {
			return nil, fmt.Errorf("could not initialize postgres Device client: %s", err)
		}
		s.Device = deviceStore
	}

	return s.Device, nil
}

func (s *PostgresStorageEngine) GetVARoleStorage() (storage.VARepo, error) {
	if s.Device == nil {
		psqlCli, err := CreatePostgresDBConnection(s.logger, s.Config, VA_DB_NAME)
		if err != nil {
			return nil, fmt.Errorf("could not create postgres client: %s", err)
		}

		m := NewMigrator(s.logger, psqlCli)
		m.MigrateToLatest()

		store, err := NewVARepository(s.logger, psqlCli)
		if err != nil {
			return nil, fmt.Errorf("could not initialize postgres Device client: %s", err)
		}
		s.VA = store
	}

	return s.VA, nil
}

func (s *PostgresStorageEngine) GetDMSStorage() (storage.DMSRepo, error) {
	if s.DMS == nil {
		psqlCli, err := CreatePostgresDBConnection(s.logger, s.Config, DMS_DB_NAME)
		if err != nil {
			return nil, fmt.Errorf("could not create postgres client: %s", err)
		}

		m := NewMigrator(s.logger, psqlCli)
		m.MigrateToLatest()

		dmsStore, err := NewDMSManagerRepository(s.logger, psqlCli)
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

	m := NewMigrator(s.logger, psqlCli)
	m.MigrateToLatest()

	if s.Subscriptions == nil {
		s.Subscriptions, err = NewSubscriptionsPostgresRepository(s.logger, psqlCli)
		if err != nil {
			return err
		}
	}

	if s.Events == nil {
		s.Events, err = NewEventsPostgresRepository(s.logger, psqlCli)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *PostgresStorageEngine) GetKMSStorage() (storage.KMSKeysRepo, error) {
	if s.KMS == nil {
		psqlCli, err := CreatePostgresDBConnection(s.logger, s.Config, KMS_DB_NAME)
		if err != nil {
			return nil, fmt.Errorf("could not create postgres client: %s", err)
		}

		m := NewMigrator(s.logger, psqlCli)
		m.MigrateToLatest()

		kmsStore, err := NewKMSPostgresRepository(s.logger, psqlCli)
		if err != nil {
			return nil, fmt.Errorf("could not initialize postgres DMS client: %s", err)
		}
		s.KMS = kmsStore
	}
	return s.KMS, nil
}
