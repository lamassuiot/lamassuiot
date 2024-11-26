//go:build experimental
// +build experimental

package couchdb

import (
	"context"
	"time"

	kivik "github.com/go-kivik/kivik/v4"
	_ "github.com/go-kivik/kivik/v4/couchdb" // The CouchDB driver
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
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

	//Check if indexes exist, and create them if not
	for field := range resources.CertificateFiltrableFields {
		querier.EnsureIndexExists(field)
	}

	return &CouchDBCertificateStorage{
		client:  client,
		querier: &querier,
	}, nil
}

func (db *CouchDBCertificateStorage) Count(ctx context.Context) (int, error) {
	return db.querier.Count(nil)
}

func (db *CouchDBCertificateStorage) CountByCAIDAndStatus(ctx context.Context, caID string, status models.CertificateStatus) (int, error) {
	opts := map[string]interface{}{
		"selector": map[string]interface{}{
			"status": map[string]interface{}{
				"$eq": status,
			},
			"issuer_metadata": map[string]interface{}{
				"id": map[string]interface{}{
					"$eq": caID,
				},
			},
		},
		"fields": []string{"_id"},
	}

	return db.querier.Count(&opts)
}

func (db *CouchDBCertificateStorage) SelectByType(ctx context.Context, CAType models.CertificateType, req storage.StorageListRequest[models.Certificate]) (string, error) {
	opts := map[string]interface{}{
		"type": CAType,
	}

	return db.querier.SelectAll(req.QueryParams, &opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *CouchDBCertificateStorage) SelectAll(ctx context.Context, req storage.StorageListRequest[models.Certificate]) (string, error) {
	return db.querier.SelectAll(req.QueryParams, &req.ExtraOpts, req.ExhaustiveRun, req.ApplyFunc)
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

func (db *CouchDBCertificateStorage) SelectByCA(ctx context.Context, caID string, req storage.StorageListRequest[models.Certificate]) (string, error) {
	opts := map[string]interface{}{
		"selector": map[string]interface{}{
			"issuer_metadata": map[string]interface{}{
				"id": map[string]interface{}{
					"$eq": caID,
				},
			},
		},
	}
	return db.querier.SelectAll(req.QueryParams, &opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *CouchDBCertificateStorage) SelectByExpirationDate(ctx context.Context, beforeExpirationDate time.Time, afterExpirationDate time.Time, req storage.StorageListRequest[models.Certificate]) (string, error) {
	opts := map[string]interface{}{
		"selector": map[string]interface{}{
			"$and": []map[string]interface{}{
				{
					"valid_to": map[string]interface{}{
						"$gt": afterExpirationDate.Format(time.RFC3339),
						"$lt": beforeExpirationDate.Format(time.RFC3339),
					},
				},
				{
					"status": map[string]interface{}{
						"$nin": []models.CertificateStatus{models.StatusExpired, models.StatusRevoked},
					},
				},
			},
		},
	}
	return db.querier.SelectAll(req.QueryParams, &opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *CouchDBCertificateStorage) SelectByCAIDAndStatus(ctx context.Context, CAID string, status models.CertificateStatus, req storage.StorageListRequest[models.Certificate]) (string, error) {
	opts := map[string]interface{}{
		"selector": map[string]interface{}{
			"$and": []map[string]interface{}{
				{
					"status": map[string]interface{}{
						"$eq": status,
					},
				},
				{
					"issuer_metadata": map[string]interface{}{
						"id": map[string]interface{}{
							"$eq": CAID,
						},
					},
				},
			},
		},
	}
	return db.querier.SelectAll(req.QueryParams, &opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *CouchDBCertificateStorage) SelectByStatus(ctx context.Context, status models.CertificateStatus, req storage.StorageListRequest[models.Certificate]) (string, error) {
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
	return db.querier.SelectAll(req.QueryParams, &opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *CouchDBCertificateStorage) CountByCA(ctx context.Context, caID string) (int, error) {
	opts := map[string]interface{}{
		"selector": map[string]interface{}{
			"issuer_metadata": map[string]interface{}{
				"id": map[string]interface{}{
					"$eq": caID,
				},
			},
		},
		"fields": []string{"_id"},
	}
	return db.querier.Count(&opts)
}

func (db *CouchDBCertificateStorage) SelectByParentCA(ctx context.Context, parentCAID string, req storage.StorageListRequest[models.Certificate]) (string, error) {
	opts := map[string]interface{}{
		"selector": map[string]interface{}{
			"issuer_metadata": map[string]interface{}{
				"id": map[string]interface{}{
					"$eq": parentCAID,
				},
			},
		},
	}
	return db.querier.SelectAll(req.QueryParams, &opts, req.ExhaustiveRun, req.ApplyFunc)
}
