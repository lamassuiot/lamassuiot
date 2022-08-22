package repository

import (
	"context"

	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/utils/common"
)

type Devices interface {
	InsertDevice(ctx context.Context, device api.Device) error
	SelectDevices(ctx context.Context, queryParameters common.QueryParameters) (int, []*api.Device, error)
	SelectDeviceById(ctx context.Context, id string) (*api.Device, error)
	UpdateDevice(ctx context.Context, device api.Device) error

	InsertSlot(ctx context.Context, deviceID string, slot api.Slot) error
	SelectSlots(ctx context.Context, deviceID string) ([]*api.Slot, error)
	SelectSlotByID(ctx context.Context, deviceID string, id string) (*api.Slot, error)
	UpdateSlot(ctx context.Context, deviceID string, slot api.Slot) error

	InsertCertificate(ctx context.Context, deviceID string, slotID string, certificate api.Certificate) error
	SelectCertificates(ctx context.Context, deviceID string, slotID string) ([]*api.Certificate, error)
	SelectCertificateBySerialNumber(ctx context.Context, deviceID string, slotID string, serialNumber string) (*api.Certificate, error)
	UpdateCertificate(ctx context.Context, deviceID string, slotID string, certificate api.Certificate) error
}

type DeviceLogs interface {
	InsertDeviceLog(ctx context.Context, deviceID string, logType api.LogType, logMessage string, logDescription string) error
	SelectDeviceLogs(ctx context.Context, deviceID string) ([]api.Log, error)

	InsertSlotLog(ctx context.Context, deviceID string, slotID string, logType api.LogType, logMessage string, logDescription string) error
	SelectSlotLogs(ctx context.Context, deviceID string, slotID string) ([]api.Log, error)
}

type Statistics interface {
	GetStatistics(ctx context.Context) (api.DevicesManagerStats, error)
	UpdateStats(ctx context.Context, stats api.DevicesManagerStats) error
}
