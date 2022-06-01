package store

import (
	"context"

	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server/filters"
)

type DB interface {
	InsertDevice(ctx context.Context, alias string, deviceID string, dmsID string, description string, tags []string, iconName string, iconColor string) error
	SelectDeviceById(ctx context.Context, id string) (dto.Device, error)
	SelectAllDevices(ctx context.Context, queryParameters filters.QueryParameters) ([]dto.Device, int, error)
	SelectAllDevicesByDmsId(ctx context.Context, dms_id string, queryParameters filters.QueryParameters) ([]dto.Device, error)
	UpdateDeviceStatusByID(ctx context.Context, id string, newStatus string) error
	UpdateDeviceCertificateSerialNumberByID(ctx context.Context, id string, serialNumber string) error
	DeleteDevice(ctx context.Context, id string) error
	UpdateByID(ctx context.Context, alias string, deviceID string, dmsID string, description string, tags []string, iconName string, iconColor string) error
	SetKeyAndSubject(ctx context.Context, keyMetadate dto.PrivateKeyMetadataWithStregth, subject dto.Subject, deviceId string) error
	InsertLog(ctx context.Context, l dto.DeviceLog) error
	SelectDeviceLogs(ctx context.Context, id string) ([]dto.DeviceLog, error)
	InsertDeviceCertHistory(ctx context.Context, l dto.DeviceCertHistory) error
	SelectDeviceCertHistory(ctx context.Context, deviceId string) ([]dto.DeviceCertHistory, error)
	SelectDeviceCertHistoryBySerialNumber(ctx context.Context, serialNumber string) (dto.DeviceCertHistory, error)
	SelectDeviceCertHistoryLastThirtyDays(ctx context.Context, queryParameters filters.QueryParameters) ([]dto.DeviceCertHistory, error)
	SelectDmssLastIssuedCert(ctx context.Context, queryParameters filters.QueryParameters) ([]dto.DMSLastIssued, error)
}
