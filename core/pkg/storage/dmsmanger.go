package storage

import (
	"context"

	"github.com/lamassuiot/lamassuiot/v2/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/resources"
)

type DMSRepo interface {
	Count(ctx context.Context) (int, error)
	SelectAll(ctx context.Context, exhaustiveRun bool, applyFunc func(models.DMS), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error)
	SelectExists(ctx context.Context, ID string) (bool, *models.DMS, error)
	Update(ctx context.Context, dms *models.DMS) (*models.DMS, error)
	Insert(ctx context.Context, dms *models.DMS) (*models.DMS, error)
}
