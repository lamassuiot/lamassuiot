package couchdb

import (
	"context"
	"fmt"

	_ "github.com/go-kivik/couchdb/v4" // The CouchDB driver
	kivik "github.com/go-kivik/kivik/v4"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/resources"
	"github.com/lamassuiot/lamassuiot/pkg/v3/storage"
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
	return db.querier.Count()
}

func (db *CouchDBCAStorage) CountByEngine(ctx context.Context, engineID string) (int, error) {
	return -1, fmt.Errorf("TODO")
}

func (db *CouchDBCAStorage) CountByStatus(ctx context.Context, status models.CertificateStatus) (int, error) {
	return -1, fmt.Errorf("TODO")
}

func (db *CouchDBCAStorage) SelectByType(ctx context.Context, CAType models.CertificateType, exhaustiveRun bool, applyFunc func(*models.CACertificate), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	opts := map[string]interface{}{
		"type": CAType,
	}
	return db.querier.SelectAll(queryParams, helpers.MergeMaps(&extraOpts, &opts), exhaustiveRun, applyFunc)
}

func (db *CouchDBCAStorage) SelectAll(ctx context.Context, exhaustiveRun bool, applyFunc func(*models.CACertificate), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	return db.querier.SelectAll(queryParams, &extraOpts, exhaustiveRun, applyFunc)
}

func (db *CouchDBCAStorage) SelectByCommonName(ctx context.Context, commonName string, exhaustiveRun bool, applyFunc func(*models.CACertificate), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	opts := map[string]interface{}{
		"selector": map[string]interface{}{
			"subject.common_name": map[string]string{
				"$eq": commonName,
			},
		},
	}
	return db.querier.SelectAll(queryParams, helpers.MergeMaps(&extraOpts, &opts), exhaustiveRun, applyFunc)
}

func (db *CouchDBCAStorage) SelectExistsByID(ctx context.Context, id string) (bool, *models.CACertificate, error) {
	return db.querier.SelectExists(id)
}

func (db *CouchDBCAStorage) SelectExistsBySerialNumber(ctx context.Context, serialNumber string) (bool, *models.CACertificate, error) {
	opts := map[string]interface{}{
		"selector": map[string]interface{}{
			"serial_number": map[string]string{
				"$eq": serialNumber,
			},
		},
	}

	var ca *models.CACertificate
	_, err := db.querier.SelectAll(&resources.QueryParameters{}, &opts, true, func(elem *models.CACertificate) {
		ca = elem
	})

	if err != nil {
		return false, nil, err
	} else if ca == nil {
		return false, nil, nil
	}

	return true, ca, nil
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
