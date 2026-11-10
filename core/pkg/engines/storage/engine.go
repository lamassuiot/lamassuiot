package storage

import (
	"sync"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/sirupsen/logrus"
)

type CommonStorageEngine struct {
	CA              CACertificatesRepo
	Cert            CertificatesRepo
	IssuanceProfile IssuanceProfileRepo
	Device          DeviceManagerRepo
	DMS             DMSRepo
	VA              VARepo
	Events          EventRepository
	Subscriptions   SubscriptionsRepository
	KMS             KMSKeysRepo
}

type StorageEngine interface {
	GetProvider() config.StorageProvider
	GetCAStorage() (CACertificatesRepo, error)
	GetCertStorage() (CertificatesRepo, error)
	GetIssuanceProfileStorage() (IssuanceProfileRepo, error)
	GetDeviceStorage() (DeviceManagerRepo, error)
	GetVARoleStorage() (VARepo, error)
	GetDMSStorage() (DMSRepo, error)
	GetEventsStorage() (EventRepository, error)
	GetSubscriptionsStorage() (SubscriptionsRepository, error)
	GetKMSStorage() (KMSKeysRepo, error)
}

// map of available storage engines with config.StorageProvider as key and function to build the storage engine as value
var (
	storageEngineBuildersMu sync.RWMutex
	storageEngineBuilders   = make(map[config.StorageProvider]func(*logrus.Entry, config.PluggableStorageEngine) (StorageEngine, error))
)

// RegisterStorageEngine registers a new storage engine
func RegisterStorageEngine(name config.StorageProvider, builder func(*logrus.Entry, config.PluggableStorageEngine) (StorageEngine, error)) {
	storageEngineBuildersMu.Lock()
	defer storageEngineBuildersMu.Unlock()

	storageEngineBuilders[name] = builder
}

func GetEngineBuilder(name config.StorageProvider) func(*logrus.Entry, config.PluggableStorageEngine) (StorageEngine, error) {
	storageEngineBuildersMu.RLock()
	defer storageEngineBuildersMu.RUnlock()

	return storageEngineBuilders[name]
}
