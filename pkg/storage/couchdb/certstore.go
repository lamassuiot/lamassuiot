package couchdb

import (
	"context"
	"fmt"
	"time"

	_ "github.com/go-kivik/couchdb/v4" // The CouchDB driver
	kivik "github.com/go-kivik/kivik/v4"
	"github.com/lamassuiot/lamassuiot/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/models"
	"github.com/lamassuiot/lamassuiot/pkg/resources"
	"github.com/lamassuiot/lamassuiot/pkg/storage"
)

const certDBName = "certificate"

type CouchDBCertificateStorage struct {
	client  *kivik.Client
	querier *couchDBQuerier[models.Certificate]
}

func NewCouchCertificateRepository(client *kivik.Client) (storage.CertificatesRepo, error) {
	err := CheckAndCreateDB(client, certDBName)
	if err != nil {
		return nil, err
	}

	querier := newCouchDBQuerier[models.Certificate](client.DB(certDBName))
	querier.CreateBasicCounterView()

	return &CouchDBCertificateStorage{
		client:  client,
		querier: &querier,
	}, nil
}

func (db *CouchDBCertificateStorage) Count(ctx context.Context) (int, error) {
	return db.querier.Count()
}

func (db *CouchDBCertificateStorage) SelectByType(ctx context.Context, CAType models.CAType, exhaustiveRun bool, applyFunc func(*models.Certificate), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	opts := map[string]interface{}{
		"type": CAType,
	}
	return db.querier.SelecAll(queryParams, helpers.MergeMaps(&extraOpts, &opts), exhaustiveRun, applyFunc)
}

func (db *CouchDBCertificateStorage) Exists(ctx context.Context, sn string) (bool, error) {
	return db.querier.Exists(sn)
}

func (db *CouchDBCertificateStorage) SelectAll(ctx context.Context, exhaustiveRun bool, applyFunc func(*models.Certificate), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	opts := map[string]interface{}{
		"selector": map[string]interface{}{
			"serial_number": map[string]string{
				"$ne": "",
			},
		},
	}

	return db.querier.SelecAll(queryParams, helpers.MergeMaps(&extraOpts, &opts), exhaustiveRun, applyFunc)
}

func (db *CouchDBCertificateStorage) Select(ctx context.Context, id string) (*models.Certificate, error) {
	return db.querier.SelectByID(id)
}

func (db *CouchDBCertificateStorage) Insert(ctx context.Context, certificate *models.Certificate) (*models.Certificate, error) {
	return db.querier.Insert(*certificate, certificate.SerialNumber)
}

func (db *CouchDBCertificateStorage) Update(ctx context.Context, certificate *models.Certificate) (*models.Certificate, error) {
	return db.querier.Update(*certificate, certificate.SerialNumber)
}

func (db *CouchDBCertificateStorage) SelectByCA(ctx context.Context, caID string, exhaustiveRun bool, applyFunc func(*models.Certificate), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	opts := map[string]interface{}{
		"selector": map[string]interface{}{
			"issuer_metadata.ca_name": map[string]string{
				"$eq": caID,
			},
		},
	}

	return db.querier.SelecAll(queryParams, helpers.MergeMaps(&extraOpts, &opts), exhaustiveRun, applyFunc)
}

func (db *CouchDBCertificateStorage) SelectByExpirationDate(ctx context.Context, beforeExpirationDate time.Time, afterExpirationDate time.Time, exhaustiveRun bool, applyFunc func(*models.Certificate), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	opts := map[string]interface{}{
		"selector": map[string]interface{}{
			"$and": []map[string]interface{}{
				{
					"valid_to": map[string]interface{}{
						"$gt": afterExpirationDate.Format(time.RFC3339),
					},
				},
				{
					"valid_to": map[string]interface{}{
						"$lt": beforeExpirationDate.Format(time.RFC3339),
					},
				},
				{
					"status": map[string]interface{}{
						"$ne": models.StatusExpired,
					},
				},
				{
					"status": map[string]interface{}{
						"$ne": models.StatusRevoked,
					},
				},
			},
		},
	}

	return db.querier.SelecAll(queryParams, helpers.MergeMaps(&extraOpts, &opts), exhaustiveRun, applyFunc)
}

func (db *CouchDBCertificateStorage) CountByCA(ctx context.Context, caID string) (int, error) {
	return -1, fmt.Errorf("TODO")
}
