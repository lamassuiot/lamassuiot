//go:build experimental
// +build experimental

package couchdb

import (
	"fmt"

	kivik "github.com/go-kivik/kivik/v4"
	config "github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage"
	log "github.com/sirupsen/logrus"
)

func init() {
	storage.RegisterStorageEngine(config.CouchDB, func(logger *log.Entry, conf config.PluggableStorageEngine) (storage.StorageEngine, error) {
		return NewStorageEngine(logger, conf.CouchDB)
	})
}

type CouchDBStorageEngine struct {
	storage.CommonStorageEngine
	Config        config.CouchDBPSEConfig
	logger        *log.Entry
	couchdbClient *kivik.Client
}

func NewStorageEngine(logger *log.Entry, config config.CouchDBPSEConfig) (storage.StorageEngine, error) {
	couchdbClient, err := CreateCouchDBConnection(logger, config)
	if err != nil {
		return nil, fmt.Errorf("could not create couchdb client: %s", err)
	}

	return &CouchDBStorageEngine{
		Config:        config,
		logger:        logger,
		couchdbClient: couchdbClient,
	}, nil
}

func (s *CouchDBStorageEngine) GetCAStorage() (storage.CACertificatesRepo, error) {

	if s.CA == nil {
		caStore, err := NewCouchCARepository(s.couchdbClient)
		s.CA = caStore
		if err != nil {
			return nil, fmt.Errorf("could not initialize couchdb CA client: %s", err)
		}
	}
	return s.CA, nil
}

func (s *CouchDBStorageEngine) GetCertstorage() (storage.CertificatesRepo, error) {
	if s.Cert == nil {
		certStore, err := NewCouchCertificateRepository(s.couchdbClient)
		s.Cert = certStore
		if err != nil {
			return nil, fmt.Errorf("could not initialize couchdb Cert client: %s", err)
		}
	}
	return s.Cert, nil
}

func (s *CouchDBStorageEngine) GetDeviceStorage() (storage.DeviceManagerRepo, error) {
	if s.Device == nil {
		deviceStore, err := NewCouchDeviceRepository(s.couchdbClient)
		s.Device = deviceStore
		if err != nil {
			return nil, fmt.Errorf("could not initialize couchdb Device client: %s", err)
		}
	}
	return s.Device, nil
}

func (s *CouchDBStorageEngine) GetDMSStorage() (storage.DMSRepo, error) {
	if s.DMS == nil {
		dmsStore, err := NewCouchDMSRepository(s.couchdbClient)
		s.DMS = dmsStore
		if err != nil {
			return nil, fmt.Errorf("could not initialize couchdb DMS client: %s", err)
		}
	}
	return s.DMS, nil
}

func (s *CouchDBStorageEngine) GetEnventsStorage() (storage.EventRepository, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *CouchDBStorageEngine) GetSubscriptionsStorage() (storage.SubscriptionsRepository, error) {
	return nil, fmt.Errorf("not implemented")
}
