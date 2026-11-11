package oracle

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	coreconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/oracle/config"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/oracle/migrations"
	"github.com/sirupsen/logrus"
)

type StorageEngine struct {
	storage.CommonStorageEngine
	pool *sql.DB
}

var _ storage.StorageEngine = (*StorageEngine)(nil)

// NewStorageEngine connects to an existing, fully migrated Oracle schema.
func NewStorageEngine(ctx context.Context, cfg config.Config) (*StorageEngine, error) {
	pool, err := openDB(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := migrations.Check(ctx, pool, migrations.Plan()); err != nil {
		_ = pool.Close()
		return nil, fmt.Errorf("check oracle schema: %w", err)
	}
	db, err := openGORM(pool, registeredPlugins...)
	if err != nil {
		_ = pool.Close()
		return nil, err
	}
	return &StorageEngine{pool: pool, CommonStorageEngine: storage.CommonStorageEngine{
		CA: &caStore{db}, Cert: &certificateStore{db}, IssuanceProfile: &issuanceProfileStore{db},
		Device: &deviceStore{db}, DMS: &dmsStore{db}, VA: &vaStore{db},
		Events: &eventStore{db}, Subscriptions: &subscriptionStore{db}, KMS: &kmsStore{db},
	}}, nil
}

// Migrate installs or upgrades the Oracle schema. DDL failures require manual
// recovery and are not automatically retried.
func Migrate(ctx context.Context, cfg config.Config) error {
	pool, err := openDB(ctx, cfg)
	if err != nil {
		return err
	}
	defer pool.Close()
	return migrations.Apply(ctx, pool, migrations.Plan())
}

func Register() {
	storage.RegisterStorageEngine(coreconfig.Oracle, func(_ *logrus.Entry, spec coreconfig.PluggableStorageEngine) (storage.StorageEngine, error) {
		cfg, err := config.Decode(spec.Config)
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return NewStorageEngine(ctx, cfg)
	})
}

func (s *StorageEngine) Close() error                                      { return s.pool.Close() }
func (*StorageEngine) GetProvider() coreconfig.StorageProvider             { return coreconfig.Oracle }
func (s *StorageEngine) GetCAStorage() (storage.CACertificatesRepo, error) { return s.CA, nil }
func (s *StorageEngine) GetCertStorage() (storage.CertificatesRepo, error) { return s.Cert, nil }
func (s *StorageEngine) GetIssuanceProfileStorage() (storage.IssuanceProfileRepo, error) {
	return s.IssuanceProfile, nil
}
func (s *StorageEngine) GetDeviceStorage() (storage.DeviceManagerRepo, error) { return s.Device, nil }
func (s *StorageEngine) GetVARoleStorage() (storage.VARepo, error)            { return s.VA, nil }
func (s *StorageEngine) GetDMSStorage() (storage.DMSRepo, error)              { return s.DMS, nil }
func (s *StorageEngine) GetEventsStorage() (storage.EventRepository, error)   { return s.Events, nil }
func (s *StorageEngine) GetSubscriptionsStorage() (storage.SubscriptionsRepository, error) {
	return s.Subscriptions, nil
}
func (s *StorageEngine) GetKMSStorage() (storage.KMSKeysRepo, error) { return s.KMS, nil }
