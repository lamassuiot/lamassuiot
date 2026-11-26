package storage

import (
	"context"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
)

type DMSRepo interface {
	Count(ctx context.Context) (int, error)
	CountWithFilters(ctx context.Context, queryParams *resources.QueryParameters) (int, error)
	SelectAll(ctx context.Context, exhaustiveRun bool, applyFunc func(models.DMS), queryParams *resources.QueryParameters, extraOpts map[string]any) (string, error)
	SelectExists(ctx context.Context, ID string) (bool, *models.DMS, error)
	Update(ctx context.Context, dms *models.DMS) (*models.DMS, error)
	Insert(ctx context.Context, dms *models.DMS) (*models.DMS, error)
	Delete(ctx context.Context, ID string) error
	// WithLock runs fn holding the lock of one RA, shared by every instance of the service, so the changes of
	// an RA and of its authz principal never interleave.
	WithLock(ctx context.Context, ID string, fn func() error) error
}
