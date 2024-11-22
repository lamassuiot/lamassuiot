//go:build experimental
// +build experimental

package couchdb

import (
	"context"

	kivik "github.com/go-kivik/kivik/v4"
	_ "github.com/go-kivik/kivik/v4/couchdb" // The CouchDB driver
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/resources"
)

type CouchDBDMSStorage struct {
	client  *kivik.Client
	querier *couchDBQuerier[models.DMS]
}

func NewCouchDMSRepository(client *kivik.Client) (storage.DMSRepo, error) {
	const dmsDBName = "dms"

	err := CheckAndCreateDB(client, dmsDBName)
	if err != nil {
		return nil, err
	}

	querier := newCouchDBQuerier[models.DMS](client.DB(dmsDBName))
	querier.CreateBasicCounterView()

	//Check if indexes exist, and create them if not
	for field := range resources.DMSFiltrableFields {
		querier.EnsureIndexExists(field)
	}

	return &CouchDBDMSStorage{
		client:  client,
		querier: &querier,
	}, nil
}

func (db *CouchDBDMSStorage) Count(ctx context.Context) (int, error) {
	return db.querier.Count(nil)
}

func (db *CouchDBDMSStorage) SelectAll(ctx context.Context, exhaustiveRun bool, applyFunc func(models.DMS), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	return db.querier.SelectAll(queryParams, &extraOpts, exhaustiveRun, applyFunc)
}

func (db *CouchDBDMSStorage) SelectExists(ctx context.Context, ID string) (bool, *models.DMS, error) {
	return db.querier.SelectExists(ID)
}

func (db *CouchDBDMSStorage) Update(ctx context.Context, dms *models.DMS) (*models.DMS, error) {
	return db.querier.Update(*dms, dms.ID)
}

func (db *CouchDBDMSStorage) Insert(ctx context.Context, dms *models.DMS) (*models.DMS, error) {
	return db.querier.Insert(*dms, dms.ID)
}
