package storage

import (
	"context"

	"github.com/lamassuiot/lamassuiot/pkg/models"
	"github.com/lamassuiot/lamassuiot/pkg/resources"
)

type DeviceManagerRepo interface {
	Count(ctx context.Context) (int, error)
	SelectAll(ctx context.Context, exhaustiveRun bool, applyFunc func(*models.Device), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error)
	Select(ctx context.Context, ID string) (*models.Device, error)
	Update(ctx context.Context, device *models.Device) (*models.Device, error)
	Insert(ctx context.Context, device *models.Device) (*models.Device, error)
}
