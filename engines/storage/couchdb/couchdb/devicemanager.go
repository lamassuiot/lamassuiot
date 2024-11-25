//go:build experimental
// +build experimental

package couchdb

import (
	"context"

	kivik "github.com/go-kivik/kivik/v4"
	_ "github.com/go-kivik/kivik/v4/couchdb" // The CouchDB driver
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
)

type CouchDBDeviceStorage struct {
	client  *kivik.Client
	querier *couchDBQuerier[models.Device]
}

func NewCouchDeviceRepository(client *kivik.Client) (storage.DeviceManagerRepo, error) {
	const deviceDBName = "device"

	err := CheckAndCreateDB(client, deviceDBName)
	if err != nil {
		return nil, err
	}

	querier := newCouchDBQuerier[models.Device](client.DB(deviceDBName))
	querier.CreateBasicCounterView()

	//Check if indexes exist, and create them if not
	for field := range resources.DeviceFiltrableFields {
		querier.EnsureIndexExists(field)
	}

	return &CouchDBDeviceStorage{
		client:  client,
		querier: &querier,
	}, nil
}

func (db *CouchDBDeviceStorage) Count(ctx context.Context) (int, error) {
	return db.querier.Count(nil)
}

func (db *CouchDBDeviceStorage) CountByStatus(ctx context.Context, status models.DeviceStatus) (int, error) {
	opts := map[string]interface{}{
		"selector": map[string]interface{}{
			"status": map[string]interface{}{
				"$eq": status,
			},
		},
		"fields": []string{"_id"},
	}

	return db.querier.Count(&opts)
}

func (db *CouchDBDeviceStorage) SelectAll(ctx context.Context, exhaustiveRun bool, applyFunc func(models.Device), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	return db.querier.SelectAll(queryParams, &extraOpts, exhaustiveRun, applyFunc)
}

func (db *CouchDBDeviceStorage) SelectExists(ctx context.Context, ID string) (bool, *models.Device, error) {
	return db.querier.SelectExists(ID)
}

func (db *CouchDBDeviceStorage) SelectByDMS(ctx context.Context, dmsID string, exhaustiveRun bool, applyFunc func(models.Device), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	opts := map[string]interface{}{
		"selector": map[string]interface{}{
			"dms_owner": map[string]string{
				"$eq": dmsID,
			},
		},
	}
	return db.querier.SelectAll(queryParams, &opts, exhaustiveRun, applyFunc)
}

func (db *CouchDBDeviceStorage) Update(ctx context.Context, device *models.Device) (*models.Device, error) {
	return db.querier.Update(*device, device.ID)
}

func (db *CouchDBDeviceStorage) Insert(ctx context.Context, device *models.Device) (*models.Device, error) {
	return db.querier.Insert(*device, device.ID)
}
