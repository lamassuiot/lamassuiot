package storage

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
