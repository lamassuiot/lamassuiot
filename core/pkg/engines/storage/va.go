package storage

import (
	"context"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
)

type VARepo interface {
	Get(ctx context.Context, caID string) (bool, *models.VARole, error)
	GetAll(ctx context.Context, req StorageListRequest[models.VARole]) (string, error)
	Update(ctx context.Context, role *models.VARole) (*models.VARole, error)
	Insert(ctx context.Context, role *models.VARole) (*models.VARole, error)
}
