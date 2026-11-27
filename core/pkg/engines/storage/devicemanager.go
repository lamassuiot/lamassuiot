package storage

import (
	"context"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
)

type DeviceManagerRepo interface {
	Count(ctx context.Context, queryParams *resources.QueryParameters) (int, error)
	SelectAll(ctx context.Context, exhaustiveRun bool, applyFunc func(models.Device), queryParams *resources.QueryParameters, extraOpts map[string]any) (string, error)
	SelectByDMS(ctx context.Context, dmsID string, exhaustiveRun bool, applyFunc func(models.Device), queryParams *resources.QueryParameters, extraOpts map[string]any) (string, error)
	SelectExists(ctx context.Context, ID string) (bool, *models.Device, error)
	Update(ctx context.Context, device *models.Device) (*models.Device, error)
	// UpdateStatus writes only the status of the device, and its identity slot when slot is not nil. A decommissioned
	// device is final: it fails with errs.ErrDeviceInvalidStatus, even when the caller read the device before its
	// decommission. It fails with errs.ErrDeviceNotFound when the device does not exist.
	UpdateStatus(ctx context.Context, ID string, status models.DeviceStatus, slot *models.Slot[string]) (*models.Device, error)
	// UpdateIdentitySlot writes only the identity slot of the device, with the same rules as UpdateStatus.
	UpdateIdentitySlot(ctx context.Context, ID string, slot *models.Slot[string]) (*models.Device, error)
	// UpdateMetadata writes only the metadata of the device, so that it never overwrites a status written meanwhile.
	// It fails with errs.ErrDeviceNotFound when the device does not exist.
	UpdateMetadata(ctx context.Context, ID string, metadata map[string]any) (*models.Device, error)
	Insert(ctx context.Context, device *models.Device) (*models.Device, error)
	Delete(ctx context.Context, ID string) error

	// DeviceGroups returns the device groups repository
	DeviceGroups() DeviceGroupsRepo

	// DeviceEvents returns the device events repository
	DeviceEvents() DeviceEventsRepo
}

type DeviceEventsRepo interface {
	Insert(ctx context.Context, event *models.DeviceEventRecord) (*models.DeviceEventRecord, error)
	SelectByDeviceID(ctx context.Context, req StorageListRequest[models.DeviceEventRecord], deviceID string) (string, error)
	DeleteByDeviceID(ctx context.Context, deviceID string) error
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
