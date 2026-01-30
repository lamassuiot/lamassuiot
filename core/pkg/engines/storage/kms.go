package storage

import (
	"context"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
)

type KMSKeysRepo interface {
	Count(ctx context.Context) (int, error)
	CountWithFilters(ctx context.Context, queryParams *resources.QueryParameters) (int, error)
	CountByEngineWithFilters(ctx context.Context, engineID string, queryParams *resources.QueryParameters) (int, error)
	SelectAll(ctx context.Context, req StorageListRequest[models.Key]) (string, error)
	SelectExistsByKeyID(ctx context.Context, id string) (bool, *models.Key, error)
	SelectExistsByAlias(ctx context.Context, alias string) (bool, *models.Key, error)

	Insert(ctx context.Context, key *models.Key) (*models.Key, error)
	Update(ctx context.Context, key *models.Key) (*models.Key, error)
	Delete(ctx context.Context, id string) error
}
