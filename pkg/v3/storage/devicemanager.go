package storage

import (
	"context"

	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/resources"
)

type DeviceManagerRepo interface {
	Count(ctx context.Context) (int, error)
	SelectAll(ctx context.Context, exhaustiveRun bool, applyFunc func(*models.Device), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error)
	SelectExists(ctx context.Context, ID string) (bool, *models.Device, error)
	Update(ctx context.Context, device *models.Device) (*models.Device, error)
	Insert(ctx context.Context, device *models.Device) (*models.Device, error)
}
