package couchdb

import (
	"context"
	"fmt"
	"net/url"
	"time"

	_ "github.com/go-kivik/couchdb/v4" // The CouchDB driver
	kivik "github.com/go-kivik/kivik/v4"
	"github.com/lamassuiot/lamassuiot/pkg/helppers"
	"github.com/lamassuiot/lamassuiot/pkg/models"
	"github.com/lamassuiot/lamassuiot/pkg/resources"
	"github.com/lamassuiot/lamassuiot/pkg/storage"
)

const certDBName = "certificate"

type CouchDBCertificateStorage struct {
	client  *kivik.Client
	querier *couchDBQuerier[models.Certificate]
}

func NewCouchCertificateRepository(couchURL url.URL, username, password string) (storage.CertificatesRepo, error) {
	client, err := createCouchDBConnection(couchURL, username, password, []string{certDBName})
	if err != nil {
		return nil, err
	}

	querier := newCouchDBQuerier[models.Certificate](client.DB(caDBName))
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
	return db.querier.SelecAll(queryParams, helppers.MergeMaps(&extraOpts, &opts), exhaustiveRun, applyFunc)
}

func (db *CouchDBCertificateStorage) SelectAll(ctx context.Context, exhaustiveRun bool, applyFunc func(*models.Certificate), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	opts := map[string]interface{}{
		"selector": map[string]interface{}{
			"serial_number": map[string]string{
				"$ne": "",
			},
		},
	}

	return db.querier.SelecAll(queryParams, helppers.MergeMaps(&extraOpts, &opts), exhaustiveRun, applyFunc)
}

func (db *CouchDBCertificateStorage) Select(ctx context.Context, id string) (*models.Certificate, error) {
	return db.querier.SelectByID(id)
}

func (db *CouchDBCertificateStorage) Insert(ctx context.Context, certificate *models.Certificate) (*models.Certificate, error) {
	return db.querier.InsertUpdate(*certificate, certificate.SerialNumber)
}

func (db *CouchDBCertificateStorage) Update(ctx context.Context, certificate *models.Certificate) (*models.Certificate, error) {
	return db.querier.InsertUpdate(*certificate, certificate.SerialNumber)
}

func (db *CouchDBCertificateStorage) SelectByCA(ctx context.Context, caID string, exhaustiveRun bool, applyFunc func(*models.Certificate), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	opts := map[string]interface{}{
		"selector": map[string]interface{}{
			"issuer_metadata.id": map[string]string{
				"$eq": caID,
			},
		},
	}

	return db.querier.SelecAll(queryParams, helppers.MergeMaps(&extraOpts, &opts), exhaustiveRun, applyFunc)
}

func (db *CouchDBCertificateStorage) SelectByExpirationDate(ctx context.Context, beforeExpirationDate time.Time, afterExpirationDate time.Time, exhaustiveRun bool, applyFunc func(*models.Certificate), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	opts := map[string]interface{}{
		"selector": map[string]interface{}{
			"$and": []map[string]interface{}{
				{
					"valid_to": map[string]interface{}{
						"$gt": afterExpirationDate.String(),
					},
				},
				{
					"valid_to": map[string]interface{}{
						"$lt": beforeExpirationDate.String(),
					},
				},
				{
					"status": map[string]interface{}{
						"$ne": models.StatusExpired,
					},
				},
				{
					"valid_to": map[string]interface{}{
						"$ne": models.StatusRevoked,
					},
				},
			},
		},
	}

	return db.querier.SelecAll(queryParams, helppers.MergeMaps(&extraOpts, &opts), exhaustiveRun, applyFunc)
}

func (db *CouchDBCertificateStorage) CountByCA(ctx context.Context, caID string) (int, error) {
	return -1, fmt.Errorf("TODO")
}
