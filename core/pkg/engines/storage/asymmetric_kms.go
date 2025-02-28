package storage

import (
	"context"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

type AsymmetricKMSRepo interface {
	Count(ctx context.Context) (int, error)
	SelectAll(ctx context.Context, req StorageListRequest[models.KeyPair]) (string, error)
	SelectExists(ctx context.Context, ID string) (bool, *models.KeyPair, error)
	Update(ctx context.Context, kp *models.KeyPair) (*models.KeyPair, error)
	Insert(ctx context.Context, kp *models.KeyPair) (*models.KeyPair, error)
	Delete(ctx context.Context, ID string) error
}
