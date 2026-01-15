package storage

import (
	"context"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
)

type DeviceManagerRepo interface {
	Count(ctx context.Context, queryParams *resources.QueryParameters) (int, error)
	SelectAll(ctx context.Context, exhaustiveRun bool, applyFunc func(models.Device), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error)
	SelectByDMS(ctx context.Context, dmsID string, exhaustiveRun bool, applyFunc func(models.Device), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error)
	SelectExists(ctx context.Context, ID string) (bool, *models.Device, error)
	Update(ctx context.Context, device *models.Device) (*models.Device, error)
	Insert(ctx context.Context, device *models.Device) (*models.Device, error)
	Delete(ctx context.Context, ID string) error
}

type DeviceGroupsRepo interface {
	// Count returns the total number of device groups
	Count(ctx context.Context) (int, error)
	
	// SelectAll returns all device groups with pagination
	SelectAll(ctx context.Context, req StorageListRequest[models.DeviceGroup]) (string, error)
	
	// SelectByID returns a device group by its ID
	SelectByID(ctx context.Context, id string) (bool, *models.DeviceGroup, error)
	
	// SelectAncestors returns all ancestor groups (parent chain) for a given group ID
	// Used for hierarchy traversal when resolving group criteria
	SelectAncestors(ctx context.Context, id string) ([]*models.DeviceGroup, error)
	
	// Insert creates a new device group
	Insert(ctx context.Context, group *models.DeviceGroup) (*models.DeviceGroup, error)
	
	// Update modifies an existing device group
	Update(ctx context.Context, group *models.DeviceGroup) (*models.DeviceGroup, error)
	
	// Delete removes a device group by ID
	Delete(ctx context.Context, id string) error
}
