package auditpub

import (
	"context"

	lservices "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/shared/subsystems/v3/pkg/eventpublisher"
)

type DeviceAuditEventPublisher struct {
	next     services.DeviceManagerService
	auditPub eventpublisher.AuditPublisher
}

func NewDeviceAuditEventPublisher(audit eventpublisher.AuditPublisher) lservices.DeviceMiddleware {
	return func(next services.DeviceManagerService) services.DeviceManagerService {
		return &DeviceAuditEventPublisher{
			next: next,
			auditPub: eventpublisher.AuditPublisher{
				ICloudEventPublisher: eventpublisher.NewEventPublisherWithSourceMiddleware(audit, models.DeviceManagerSource),
			},
		}
	}
}

func (mw *DeviceAuditEventPublisher) GetDevicesStats(ctx context.Context, input services.GetDevicesStatsInput) (*models.DevicesStats, error) {
	return mw.next.GetDevicesStats(ctx, input)
}

func (mw *DeviceAuditEventPublisher) CreateDevice(ctx context.Context, input services.CreateDeviceInput) (output *models.Device, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventCreateDeviceKey, input, err, output)
	}()

	return mw.next.CreateDevice(ctx, input)
}

func (mw *DeviceAuditEventPublisher) GetDeviceByID(ctx context.Context, input services.GetDeviceByIDInput) (*models.Device, error) {
	return mw.next.GetDeviceByID(ctx, input)
}

func (mw *DeviceAuditEventPublisher) GetDevices(ctx context.Context, input services.GetDevicesInput) (string, error) {
	return mw.next.GetDevices(ctx, input)
}

func (mw *DeviceAuditEventPublisher) GetDeviceByDMS(ctx context.Context, input services.GetDevicesByDMSInput) (string, error) {
	return mw.next.GetDeviceByDMS(ctx, input)
}

func (mw *DeviceAuditEventPublisher) UpdateDeviceStatus(ctx context.Context, input services.UpdateDeviceStatusInput) (output *models.Device, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventUpdateDeviceStatusKey, input, err, output)
	}()

	return mw.next.UpdateDeviceStatus(ctx, input)
}

func (mw *DeviceAuditEventPublisher) UpdateDeviceIdentitySlot(ctx context.Context, input services.UpdateDeviceIdentitySlotInput) (output *models.Device, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventUpdateDeviceIDSlotKey, input, err, output)
	}()

	return mw.next.UpdateDeviceIdentitySlot(ctx, input)
}

func (mw *DeviceAuditEventPublisher) UpdateDeviceMetadata(ctx context.Context, input services.UpdateDeviceMetadataInput) (output *models.Device, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventUpdateDeviceMetadataKey, input, err, output)
	}()

	return mw.next.UpdateDeviceMetadata(ctx, input)
}

func (mw *DeviceAuditEventPublisher) DeleteDevice(ctx context.Context, input services.DeleteDeviceInput) (err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventDeleteDeviceKey, input, err, nil)
	}()
	return mw.next.DeleteDevice(ctx, input)
}
