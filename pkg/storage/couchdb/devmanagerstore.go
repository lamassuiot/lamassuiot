package couchdb

import (
	"context"
	"net/url"

	_ "github.com/go-kivik/couchdb/v4" // The CouchDB driver
	kivik "github.com/go-kivik/kivik/v4"
	"github.com/lamassuiot/lamassuiot/pkg/models"
	"github.com/lamassuiot/lamassuiot/pkg/resources"
	"github.com/lamassuiot/lamassuiot/pkg/storage"
)

const deviceDB = "device"

type CouchDBDeviceManagerStorage struct {
	client  *kivik.Client
	querier *couchDBQuerier[models.Device]
}

func NewCouchDeviceManagerSRepository(couchURL url.URL, username, password string) (storage.DeviceManagerRepo, error) {

	client, err := createCouchDBConnection(couchURL, username, password, []string{deviceDB})
	if err != nil {
		return nil, err
	}

	querier := newCouchDBQuerier[models.Device](client.DB(caDBName))
	querier.CreateBasicCounterView()

	return &CouchDBDeviceManagerStorage{
		client:  client,
		querier: &querier,
	}, nil
}

func (db *CouchDBDeviceManagerStorage) Count(ctx context.Context) (int, error) {
	return db.querier.Count()
}

func (db *CouchDBDeviceManagerStorage) SelectAll(ctx context.Context, exhaustiveRun bool, applyFunc func(*models.Device), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	return db.querier.SelecAll(queryParams, &extraOpts, exhaustiveRun, applyFunc)
}

func (db *CouchDBDeviceManagerStorage) Select(ctx context.Context, ID string) (*models.Device, error) {
	return db.querier.SelectByID(ID)
}

func (db *CouchDBDeviceManagerStorage) Update(ctx context.Context, device *models.Device) (*models.Device, error) {
	return db.querier.InsertUpdate(*device, device.ID)
}

func (db *CouchDBDeviceManagerStorage) Insert(ctx context.Context, device *models.Device) (*models.Device, error) {
	return db.querier.InsertUpdate(*device, device.ID)
}
