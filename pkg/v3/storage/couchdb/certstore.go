package couchdb

import (
	"context"
	"fmt"
	"time"

	_ "github.com/go-kivik/couchdb/v4" // The CouchDB driver
	kivik "github.com/go-kivik/kivik/v4"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/resources"
	"github.com/lamassuiot/lamassuiot/pkg/v3/storage"
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

func (db *CouchDBCertificateStorage) SelectByType(ctx context.Context, CAType models.CertificateType, exhaustiveRun bool, applyFunc func(*models.Certificate), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	opts := map[string]interface{}{
		"type": CAType,
	}
	return db.querier.SelectAll(queryParams, helpers.MergeMaps(&extraOpts, &opts), exhaustiveRun, applyFunc)
}

func (db *CouchDBCertificateStorage) SelectAll(ctx context.Context, exhaustiveRun bool, applyFunc func(*models.Certificate), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	opts := map[string]interface{}{
		"selector": map[string]interface{}{
			"serial_number": map[string]string{
				"$ne": "",
			},
		},
	}

	return db.querier.SelectAll(queryParams, helpers.MergeMaps(&extraOpts, &opts), exhaustiveRun, applyFunc)
}

func (db *CouchDBCertificateStorage) SelectExistsBySerialNumber(ctx context.Context, id string) (bool, *models.Certificate, error) {
	return db.querier.SelectExists(id)
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

	return db.querier.SelectAll(queryParams, helpers.MergeMaps(&extraOpts, &opts), exhaustiveRun, applyFunc)
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

	return db.querier.SelectAll(queryParams, helpers.MergeMaps(&extraOpts, &opts), exhaustiveRun, applyFunc)
}

func (db *CouchDBCertificateStorage) SelectByCAIDAndStatus(ctx context.Context, CAID string, status models.CertificateStatus, exhaustiveRun bool, applyFunc func(*models.Certificate), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	opts := map[string]interface{}{
		"selector": map[string]interface{}{
			"$and": []map[string]interface{}{
				{
					"status": map[string]interface{}{
						"$eq": status,
					},
				},
				{
					"issuer_metadata.ca_id": map[string]interface{}{
						"$eq": CAID,
					},
				},
			},
		},
	}
	return db.querier.SelectAll(queryParams, helpers.MergeMaps(&extraOpts, &opts), exhaustiveRun, applyFunc)
}

func (db *CouchDBCertificateStorage) SelectByStatus(ctx context.Context, status models.CertificateStatus, exhaustiveRun bool, applyFunc func(*models.Certificate), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	opts := map[string]interface{}{
		"selector": map[string]interface{}{
			"$and": []map[string]interface{}{
				{
					"status": map[string]interface{}{
						"$eq": status,
					},
				},
			},
		},
	}
	return db.querier.SelectAll(queryParams, helpers.MergeMaps(&extraOpts, &opts), exhaustiveRun, applyFunc)
}

func (db *CouchDBCertificateStorage) CountByCA(ctx context.Context, caID string) (int, error) {
	return -1, fmt.Errorf("TODO")
}
