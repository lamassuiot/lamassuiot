package storage

import (
	"context"

	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/resources"
)

type DeviceManagerRepo interface {
	Count(ctx context.Context) (int, error)
	CountByStatus(ctx context.Context, status models.DeviceStatus) (int, error)
	SelectAll(ctx context.Context, exhaustiveRun bool, applyFunc func(models.Device), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error)
	SelectByDMS(ctx context.Context, dmsID string, exhaustiveRun bool, applyFunc func(models.Device), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error)
	SelectExists(ctx context.Context, ID string) (bool, *models.Device, error)
	Update(ctx context.Context, device *models.Device) (*models.Device, error)
	Insert(ctx context.Context, device *models.Device) (*models.Device, error)
}

type DeviceEventsRepo interface {
	InsertEvent(ctx context.Context, event *models.DeviceEvent) (*models.DeviceEvent, error)
	SelectEvents(ctx context.Context, deviceID string, applyFunc func(models.DeviceEvent), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error)
}
