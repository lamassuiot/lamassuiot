package storage

import (
	"context"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

type KMSKeysRepo interface {
	Count(ctx context.Context) (int, error)
	SelectAll(ctx context.Context, req StorageListRequest[models.Key]) (string, error)
	SelectExistsByKeyID(ctx context.Context, id string) (bool, *models.Key, error)
	SelectExistsByAlias(ctx context.Context, alias string) (bool, *models.Key, error)

	Insert(ctx context.Context, key *models.Key) (*models.Key, error)
	Update(ctx context.Context, key *models.Key) (*models.Key, error)
	Delete(ctx context.Context, id string) error
}
