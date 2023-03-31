package couchdb

import (
	"context"

	_ "github.com/go-kivik/couchdb/v4" // The CouchDB driver
	kivik "github.com/go-kivik/kivik/v4"
	"github.com/lamassuiot/lamassuiot/pkg/config"
	"github.com/lamassuiot/lamassuiot/pkg/models"
	"github.com/lamassuiot/lamassuiot/pkg/resources"
	"github.com/lamassuiot/lamassuiot/pkg/storage"
)

const dmsDB = "dms"

type CouchDBDMSStorage struct {
	client  *kivik.Client
	querier *couchDBQuerier[models.DMS]
}

func NewCouchDMSRepository(cfg config.HTTPConnection, username, password string) (storage.DMSRepo, error) {
	client, err := createCouchDBConnection(cfg, username, password, []string{dmsDB})
	if err != nil {
		return nil, err
	}

	querier := newCouchDBQuerier[models.DMS](client.DB(caDBName))
	querier.CreateBasicCounterView()

	return &CouchDBDMSStorage{
		client:  client,
		querier: &querier,
	}, nil
}

func (db *CouchDBDMSStorage) Count(ctx context.Context) (int, error) {
	return db.querier.Count()
}

func (db *CouchDBDMSStorage) SelectAll(ctx context.Context, exhaustiveRun bool, applyFunc func(*models.DMS), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	return db.querier.SelecAll(queryParams, &extraOpts, exhaustiveRun, applyFunc)
}

func (db *CouchDBDMSStorage) Select(ctx context.Context, ID string) (*models.DMS, error) {
	return db.querier.SelectByID(ID)
}

func (db *CouchDBDMSStorage) Update(ctx context.Context, dms *models.DMS) (*models.DMS, error) {
	return db.querier.Update(*dms, dms.ID)
}

func (db *CouchDBDMSStorage) Insert(ctx context.Context, dms *models.DMS) (*models.DMS, error) {
	return db.querier.Insert(*dms, dms.ID)
}
