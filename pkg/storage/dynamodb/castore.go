package dynamodb

import (
	"context"
	"math/rand"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/lamassuiot/lamassuiot/pkg/models"
	"github.com/lamassuiot/lamassuiot/pkg/resources"
	"github.com/lamassuiot/lamassuiot/pkg/storage"
)

type DynamoDBCAStorage struct {
	client       *dynamodb.Client
	querier      *dynamoDBQuerier[models.CACertificate]
	customerName string
}

func NewDynamoDBCARepository(ctx context.Context, tableName, region, accessKeyID, secretAccessKey, url, customerName string) (storage.CACertificatesRepo, error) {
	client, err := CreateDynamoDBConnection(ctx, region, accessKeyID, secretAccessKey, url)
	if err != nil {
		return nil, err
	}

	querier := newDynamoDBQuerier[models.CACertificate](client, tableName)

	return &DynamoDBCAStorage{
		client:       client,
		querier:      &querier,
		customerName: customerName,
	}, nil
}

func (db *DynamoDBCAStorage) Count(ctx context.Context) (int, error) {
	//TODO: Not implemented yet
	return 0, nil
}

func (db *DynamoDBCAStorage) Exists(ctx context.Context, id string) (bool, error) {
	return db.querier.Exists(ctx, "CA#"+id, "CA#"+id)

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
	PK := "CA#" + caCertificate.ID
	SK := "CA#" + caCertificate.ID
	indexAttributes := map[string]interface{}{
		"GSI1PK": "Customer#" + db.customerName + "#" + strconv.Itoa(rand.Intn(10)),
		"GSI1SK": "CA#" + caCertificate.ID,
	}
	return db.querier.Insert(ctx, *caCertificate, PK, SK, indexAttributes)
}

func (db *DynamoDBCAStorage) Update(ctx context.Context, caCertificate *models.CACertificate) (*models.CACertificate, error) {
	return db.querier.Update(ctx, *caCertificate, "CA#"+caCertificate.ID, "CA#"+caCertificate.ID)
}
