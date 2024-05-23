package storage

import (
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/sirupsen/logrus"
)

type CommonStorageEngine struct {
	CA            CACertificatesRepo
	Cert          CertificatesRepo
	Device        DeviceManagerRepo
	DMS           DMSRepo
	Events        EventRepository
	Subscriptions SubscriptionsRepository
}

type StorageEngine interface {
	GetCAStorage() (CACertificatesRepo, error)
	GetCertstorage() (CertificatesRepo, error)
	GetDeviceStorage() (DeviceManagerRepo, error)
	GetDMSStorage() (DMSRepo, error)
	GetEnventsStorage() (EventRepository, error)
	GetSubscriptionsStorage() (SubscriptionsRepository, error)
}

// map of available storage engines with config.StorageProvider as key and function to build the storage engine as value
var storageEngineBuilders = make(map[config.StorageProvider]func(*logrus.Entry, config.PluggableStorageEngine) (StorageEngine, error))

// RegisterStorageEngine registers a new storage engine
func RegisterStorageEngine(name config.StorageProvider, builder func(*logrus.Entry, config.PluggableStorageEngine) (StorageEngine, error)) {
	storageEngineBuilders[name] = builder
}

func GetEngineBuilder(name config.StorageProvider) func(*logrus.Entry, config.PluggableStorageEngine) (StorageEngine, error) {
	return storageEngineBuilders[name]
}
