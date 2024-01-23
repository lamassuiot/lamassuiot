//go:build experimental
// +build experimental

package couchdb

import (
	"context"

	_ "github.com/go-kivik/couchdb/v4" // The CouchDB driver
	kivik "github.com/go-kivik/kivik/v4"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage"
)

const caDBName = "certificate-authority"

type CouchDBCAStorage struct {
	client  *kivik.Client
	querier *couchDBQuerier[models.CACertificate]
}

func NewCouchCARepository(client *kivik.Client) (storage.CACertificatesRepo, error) {
	err := CheckAndCreateDB(client, caDBName)
	if err != nil {
		return nil, err
	}

	querier := newCouchDBQuerier[models.CACertificate](client.DB(caDBName))
	querier.CreateBasicCounterView()

	return &CouchDBCAStorage{
		client:  client,
		querier: &querier,
	}, nil
}

func (db *CouchDBCAStorage) Count(ctx context.Context) (int, error) {
	return db.querier.Count(nil)
}

func (db *CouchDBCAStorage) CountByEngine(ctx context.Context, engineID string) (int, error) {
	countByEngineCAOpts := map[string]interface{}{
		"selector": map[string]interface{}{
			"engine_id": map[string]interface{}{
				"$eq": engineID,
			},
		},
		"fields": []string{"_id"},
	}
	return db.querier.Count(&countByEngineCAOpts)
}

func (db *CouchDBCAStorage) CountByStatus(ctx context.Context, status models.CertificateStatus) (int, error) {
	countByStatusCAOpts := map[string]interface{}{
		"selector": map[string]interface{}{
			"status": map[string]interface{}{
				"$eq": status,
			},
		},
		"fields": []string{"_id"},
	}
	return db.querier.Count(&countByStatusCAOpts)
}

func (db *CouchDBCAStorage) SelectByType(ctx context.Context, CAType models.CertificateType, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	selectTypeCAOpts := map[string]interface{}{
		"selector": map[string]interface{}{
			"type": CAType,
		},
	}
	return db.querier.SelectAll(req.QueryParams, &selectTypeCAOpts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *CouchDBCAStorage) SelectAll(ctx context.Context, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	return db.querier.SelectAll(req.QueryParams, &req.ExtraOpts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *CouchDBCAStorage) SelectByCommonName(ctx context.Context, commonName string, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	selectByCommonNameCAOpts := map[string]interface{}{
		"selector": map[string]interface{}{
			"_id": map[string]string{
				"$ne": commonName,
			},
		},
	}

	return db.querier.SelectAll(req.QueryParams, &selectByCommonNameCAOpts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *CouchDBCAStorage) SelectExistsByID(ctx context.Context, id string) (bool, *models.CACertificate, error) {
	return db.querier.SelectExists(id)
}

func (db *CouchDBCAStorage) SelectByParentCA(ctx context.Context, parentCAID string, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	selectByParentCAOpts := map[string]interface{}{
		"selector": map[string]interface{}{
			"parentCA": parentCAID,
		},
	}

	return db.querier.SelectAll(req.QueryParams, &selectByParentCAOpts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *CouchDBCAStorage) SelectExistsBySerialNumber(ctx context.Context, serialNumber string) (bool, *models.CACertificate, error) {
	return db.querier.SelectExists(serialNumber)
}

func (db *CouchDBCAStorage) Insert(ctx context.Context, caCertificate *models.CACertificate) (*models.CACertificate, error) {
	return db.querier.Insert(*caCertificate, caCertificate.ID)
}

func (db *CouchDBCAStorage) Update(ctx context.Context, caCertificate *models.CACertificate) (*models.CACertificate, error) {
	return db.querier.Update(*caCertificate, caCertificate.ID)
}

func (db *CouchDBCAStorage) Delete(ctx context.Context, id string) error {
	return db.querier.Delete(id)
}
