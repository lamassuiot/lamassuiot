package sqlite

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type SQLiteStorageEngine struct {
	storage.CommonStorageEngine
	db     *gorm.DB
	logger *logrus.Entry
}

func Register() {
	storage.RegisterStorageEngine(config.SQLite, func(logger *logrus.Entry, conf config.PluggableStorageEngine) (storage.StorageEngine, error) {
		path, ok := conf.Config["path"].(string)
		if !ok {
			path = "file::memory:?cache=shared"
		}

		db, err := CreateSQLiteDBConnection(logger, path)
		if err != nil {
			return nil, fmt.Errorf("could not create sqlite connection: %s", err)
		}

		if err := initializeSchema(db); err != nil {
			return nil, fmt.Errorf("could not initialize sqlite schema: %s", err)
		}

		return &SQLiteStorageEngine{
			db:     db,
			logger: logger,
		}, nil
	})
}

func (s *SQLiteStorageEngine) GetProvider() config.StorageProvider {
	return config.SQLite
}

func (s *SQLiteStorageEngine) GetCAStorage() (storage.CACertificatesRepo, error) {
	if s.CA == nil {
		if err := s.initCAStorage(); err != nil {
			return nil, err
		}
	}
	return s.CA, nil
}

func (s *SQLiteStorageEngine) GetCertStorage() (storage.CertificatesRepo, error) {
	if s.Cert == nil {
		if err := s.initCAStorage(); err != nil {
			return nil, err
		}
	}
	return s.Cert, nil
}

func (s *SQLiteStorageEngine) GetIssuanceProfileStorage() (storage.IssuanceProfileRepo, error) {
	if s.IssuanceProfile == nil {
		if err := s.initCAStorage(); err != nil {
			return nil, err
		}
	}
	return s.IssuanceProfile, nil
}

func (s *SQLiteStorageEngine) initCAStorage() error {
	var err error
	if s.CA == nil {
		s.CA, err = postgres.NewCAPostgresRepository(s.logger, s.db)
		if err != nil {
			return err
		}
	}
	if s.Cert == nil {
		s.Cert, err = postgres.NewCertificateRepository(s.logger, s.db)
		if err != nil {
			return err
		}
	}
	if s.IssuanceProfile == nil {
		s.IssuanceProfile, err = postgres.NewIssuanceProfileRepository(s.logger, s.db)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLiteStorageEngine) initDeviceStorage() error {
	var err error
	if s.Device == nil {
		s.Device, err = postgres.NewDeviceManagerRepository(s.logger, s.db)
		if err != nil {
			return err
		}
	}

	if s.DeviceStatus == nil {
		s.DeviceStatus, err = postgres.NewDeviceStatusRepository(s.logger, s.db)
		if err != nil {
			return err
		}
	}

	if s.DeviceEvents == nil {
		s.DeviceEvents, err = postgres.NewDeviceEventsRepository(s.logger, s.db)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLiteStorageEngine) GetDeviceStorage() (storage.DeviceManagerRepo, error) {
	if s.Device == nil {
		err := s.initDeviceStorage()
		if err != nil {
			return nil, fmt.Errorf("could not initialize sqlite Device client: %s", err)
		}
	}
	return s.Device, nil
}

func (s *SQLiteStorageEngine) GetDeviceStatusStorage() (storage.DeviceStatusRepo, error) {
	if s.DeviceStatus == nil {
		err := s.initDeviceStorage()
		if err != nil {
			return nil, fmt.Errorf("could not initialize sqlite Device Status client: %s", err)
		}
	}
	return s.DeviceStatus, nil
}

func (s *SQLiteStorageEngine) GetDeviceEventStorage() (storage.DeviceEventsRepo, error) {
	if s.DeviceEvents == nil {
		err := s.initDeviceStorage()
		if err != nil {
			return nil, fmt.Errorf("could not initialize sqlite Device Events client: %s", err)
		}
	}
	return s.DeviceEvents, nil
}

func (s *SQLiteStorageEngine) GetVARoleStorage() (storage.VARepo, error) {
	if s.VA == nil {
		var err error
		s.VA, err = postgres.NewVARepository(s.logger, s.db)
		if err != nil {
			return nil, err
		}
	}
	return s.VA, nil
}

func (s *SQLiteStorageEngine) GetDMSStorage() (storage.DMSRepo, error) {
	if s.DMS == nil {
		var err error
		s.DMS, err = postgres.NewDMSManagerRepository(s.logger, s.db)
		if err != nil {
			return nil, err
		}
	}
	return s.DMS, nil
}

func (s *SQLiteStorageEngine) GetEnventsStorage() (storage.EventRepository, error) {
	if s.Events == nil {
		if err := s.initEventsStorage(); err != nil {
			return nil, err
		}
	}
	return s.Events, nil
}

func (s *SQLiteStorageEngine) GetSubscriptionsStorage() (storage.SubscriptionsRepository, error) {
	if s.Subscriptions == nil {
		if err := s.initEventsStorage(); err != nil {
			return nil, err
		}
	}
	return s.Subscriptions, nil
}

func (s *SQLiteStorageEngine) initEventsStorage() error {
	var err error
	if s.Events == nil {
		s.Events, err = postgres.NewEventsPostgresRepository(s.logger, s.db)
		if err != nil {
			return err
		}
	}
	if s.Subscriptions == nil {
		s.Subscriptions, err = postgres.NewSubscriptionsPostgresRepository(s.logger, s.db)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLiteStorageEngine) GetKMSStorage() (storage.KMSKeysRepo, error) {
	if s.KMS == nil {
		var err error
		s.KMS, err = postgres.NewKMSPostgresRepository(s.logger, s.db)
		if err != nil {
			return nil, err
		}
	}
	return s.KMS, nil
}
