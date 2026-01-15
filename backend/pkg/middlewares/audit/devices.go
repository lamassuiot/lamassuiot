package auditpub

import (
	"context"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/middlewares/eventpub"
	lservices "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

type DeviceAuditEventPublisher struct {
	next     services.DeviceManagerService
	auditPub AuditPublisher
}

func NewDeviceAuditEventPublisher(audit AuditPublisher) lservices.DeviceMiddleware {
	return func(next services.DeviceManagerService) services.DeviceManagerService {
		return &DeviceAuditEventPublisher{
			next: next,
			auditPub: AuditPublisher{
				ICloudEventPublisher: eventpub.NewEventPublisherWithSourceMiddleware(audit, models.DeviceManagerSource),
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

// ============================================================================
// Device Group Operations
// ============================================================================

func (mw *DeviceAuditEventPublisher) CreateDeviceGroup(ctx context.Context, input services.CreateDeviceGroupInput) (output *models.DeviceGroup, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventCreateDeviceGroupKey, input, err, output)
	}()
	return mw.next.CreateDeviceGroup(ctx, input)
}

func (mw *DeviceAuditEventPublisher) UpdateDeviceGroup(ctx context.Context, input services.UpdateDeviceGroupInput) (output *models.DeviceGroup, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventUpdateDeviceGroupKey, input, err, output)
	}()
	return mw.next.UpdateDeviceGroup(ctx, input)
}

func (mw *DeviceAuditEventPublisher) DeleteDeviceGroup(ctx context.Context, input services.DeleteDeviceGroupInput) (err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventDeleteDeviceGroupKey, input, err, nil)
	}()
	return mw.next.DeleteDeviceGroup(ctx, input)
}

func (mw *DeviceAuditEventPublisher) GetDeviceGroupByID(ctx context.Context, input services.GetDeviceGroupByIDInput) (*models.DeviceGroup, error) {
	return mw.next.GetDeviceGroupByID(ctx, input)
}

func (mw *DeviceAuditEventPublisher) GetDeviceGroups(ctx context.Context, input services.GetDeviceGroupsInput) (string, error) {
	return mw.next.GetDeviceGroups(ctx, input)
}

func (mw *DeviceAuditEventPublisher) GetDevicesByGroup(ctx context.Context, input services.GetDevicesByGroupInput) (string, error) {
	return mw.next.GetDevicesByGroup(ctx, input)
}

func (mw *DeviceAuditEventPublisher) GetDeviceGroupStats(ctx context.Context, input services.GetDeviceGroupStatsInput) (*models.DevicesStats, error) {
	return mw.next.GetDeviceGroupStats(ctx, input)
}
