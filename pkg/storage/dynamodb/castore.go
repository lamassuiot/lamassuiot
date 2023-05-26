package dynamodb

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/lamassuiot/lamassuiot/pkg/models"
	"github.com/lamassuiot/lamassuiot/pkg/resources"
	"github.com/lamassuiot/lamassuiot/pkg/storage"
)

type DynamoDBCAStorage struct {
	client  *dynamodb.Client
	querier *dynamoDBQuerier[models.CACertificate]
}

func NewDynamoDBCARepository(ctx context.Context, tableName, region, accessKeyID, secretAccessKey, url string) (storage.CACertificatesRepo, error) {
	client, err := createDynamoDBConnection(ctx, region, accessKeyID, secretAccessKey, url)
	if err != nil {
		return nil, err
	}

	querier := newDynamoDBQuerier[models.CACertificate](client, tableName)

	return &DynamoDBCAStorage{
		client:  client,
		querier: &querier,
	}, nil
}

func (db *DynamoDBCAStorage) Count(ctx context.Context) (int, error) {
	//TODO: Not implemented yet
	return 0, nil
}

func (db *DynamoDBCAStorage) Exists(ctx context.Context, sn string) (bool, error) {
	// TODO: Not implemented yet
	return false, nil
}

func (db *DynamoDBCAStorage) SelectByType(ctx context.Context, CAType models.CAType, exhaustiveRun bool, applyFunc func(*models.CACertificate), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	//TODO: Not implemented yet
	return "", nil
}

func (db *DynamoDBCAStorage) SelectAll(ctx context.Context, exhaustiveRun bool, applyFunc func(*models.CACertificate), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	//TODO: Not implemented yet
	return "", nil
}

func (db *DynamoDBCAStorage) Select(ctx context.Context, id string) (*models.CACertificate, error) {
	return db.querier.Select(ctx, "CA#"+id, "CA#"+id)
}

func (db *DynamoDBCAStorage) Insert(ctx context.Context, caCertificate *models.CACertificate) (*models.CACertificate, error) {
	return db.querier.Insert(ctx, *caCertificate, "CA#"+caCertificate.ID, "CA#"+caCertificate.ID)
}

func (db *DynamoDBCAStorage) Update(ctx context.Context, caCertificate *models.CACertificate) (*models.CACertificate, error) {
	return db.querier.Update(ctx, *caCertificate, "CA#"+caCertificate.ID, "CA#"+caCertificate.ID)
}

func (db *DynamoDBCAStorage) Clean(ctx context.Context) error {
	return db.querier.Clean(ctx)
}
