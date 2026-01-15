package services

import (
	"context"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
)

type DeviceManagerService interface {
	GetDevicesStats(ctx context.Context, input GetDevicesStatsInput) (*models.DevicesStats, error)
	CreateDevice(ctx context.Context, input CreateDeviceInput) (*models.Device, error)
	GetDeviceByID(ctx context.Context, input GetDeviceByIDInput) (*models.Device, error)
	GetDevices(ctx context.Context, input GetDevicesInput) (string, error)
	GetDeviceByDMS(ctx context.Context, input GetDevicesByDMSInput) (string, error)
	UpdateDeviceStatus(ctx context.Context, input UpdateDeviceStatusInput) (*models.Device, error)
	UpdateDeviceIdentitySlot(ctx context.Context, input UpdateDeviceIdentitySlotInput) (*models.Device, error)
	UpdateDeviceMetadata(ctx context.Context, input UpdateDeviceMetadataInput) (*models.Device, error)
	DeleteDevice(ctx context.Context, input DeleteDeviceInput) error

	// Device Group operations
	CreateDeviceGroup(ctx context.Context, input CreateDeviceGroupInput) (*models.DeviceGroup, error)
	UpdateDeviceGroup(ctx context.Context, input UpdateDeviceGroupInput) (*models.DeviceGroup, error)
	DeleteDeviceGroup(ctx context.Context, input DeleteDeviceGroupInput) error
	GetDeviceGroupByID(ctx context.Context, input GetDeviceGroupByIDInput) (*models.DeviceGroup, error)
	GetDeviceGroups(ctx context.Context, input GetDeviceGroupsInput) (string, error)
	GetDevicesByGroup(ctx context.Context, input GetDevicesByGroupInput) (string, error)
	GetDeviceGroupStats(ctx context.Context, input GetDeviceGroupStatsInput) (*models.DevicesStats, error)
}

type GetDevicesStatsInput struct {
	QueryParameters *resources.QueryParameters
}

type CreateDeviceInput struct {
	ID        string `validate:"required"`
	Alias     string
	Tags      []string
	Metadata  map[string]any
	DMSID     string `validate:"required"`
	Icon      string `validate:"required"`
	IconColor string `validate:"required"`
}

type ProvisionDeviceSlotInput struct {
	ID     string `validate:"required"`
	SlotID string `validate:"required"`
}

type GetDevicesInput struct {
	resources.ListInput[models.Device]
}

type GetDevicesByDMSInput struct {
	DMSID string
	resources.ListInput[models.Device]
}

type GetDeviceByIDInput struct {
	ID string `validate:"required"`
}

type UpdateDeviceStatusInput struct {
	ID        string              `validate:"required"`
	NewStatus models.DeviceStatus `validate:"required"`
}

type UpdateDeviceMetadataInput struct {
	ID      string                  `validate:"required"`
	Patches []models.PatchOperation `validate:"required"`
}

type UpdateDeviceIdentitySlotInput struct {
	ID   string              `validate:"required"`
	Slot models.Slot[string] `validate:"required"`
}

type DeleteDeviceInput struct {
	ID string `validate:"required"`
}

// Device Group Input/Output Structs

type CreateDeviceGroupInput struct {
	ID          string `validate:"required"`
	Name        string `validate:"required"`
	Description string
	ParentID    *string
	Criteria    []models.DeviceGroupFilterOption `validate:"required"`
}

type UpdateDeviceGroupInput struct {
	ID          string `validate:"required"`
	Name        string
	Description string
	ParentID    *string
	Criteria    []models.DeviceGroupFilterOption
}

type DeleteDeviceGroupInput struct {
	ID string `validate:"required"`
}

type GetDeviceGroupByIDInput struct {
	ID string `validate:"required"`
}

type GetDeviceGroupsInput struct {
	resources.ListInput[models.DeviceGroup]
}

type GetDevicesByGroupInput struct {
	GroupID string `validate:"required"`
	resources.ListInput[models.Device]
}

type GetDeviceGroupStatsInput struct {
	GroupID string `validate:"required"`
}
