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
}

type GetDevicesStatsInput struct {
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
