package eventpub

import (
	"context"
	"fmt"

	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
)

type deviceEventPublisher struct {
	next       services.DeviceManagerService
	eventMWPub ICloudEventMiddlewarePublisher
}

func NewDeviceEventPublisher(eventMWPub ICloudEventMiddlewarePublisher) services.DeviceMiddleware {
	return func(next services.DeviceManagerService) services.DeviceManagerService {
		return &deviceEventPublisher{
			next:       next,
			eventMWPub: eventMWPub,
		}
	}
}

func (mw *deviceEventPublisher) GetDevicesStats(ctx context.Context, input services.GetDevicesStatsInput) (*models.DevicesStats, error) {
	return mw.next.GetDevicesStats(ctx, input)
}

func (mw *deviceEventPublisher) CreateDevice(ctx context.Context, input services.CreateDeviceInput) (output *models.Device, err error) {
	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(context.Background(), models.EventCreateDeviceKey, output)
		}
	}()
	return mw.next.CreateDevice(ctx, input)
}

func (mw *deviceEventPublisher) GetDeviceByID(ctx context.Context, input services.GetDeviceByIDInput) (*models.Device, error) {
	return mw.next.GetDeviceByID(ctx, input)
}

func (mw *deviceEventPublisher) GetDevices(ctx context.Context, input services.GetDevicesInput) (string, error) {
	return mw.next.GetDevices(ctx, input)
}

func (mw *deviceEventPublisher) GetDeviceByDMS(ctx context.Context, input services.GetDevicesByDMSInput) (string, error) {
	return mw.next.GetDeviceByDMS(ctx, input)
}

func (mw *deviceEventPublisher) UpdateDeviceStatus(ctx context.Context, input services.UpdateDeviceStatusInput) (output *models.Device, err error) {
	prev, err := mw.GetDeviceByID(ctx, services.GetDeviceByIDInput{
		ID: input.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get Device %s: %w", input.ID, err)
	}

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(context.Background(), models.EventUpdateDeviceStatusKey, models.UpdateModel[models.Device]{
				Updated:  *output,
				Previous: *prev,
			})
		}
	}()
	return mw.next.UpdateDeviceStatus(ctx, input)
}

func (mw *deviceEventPublisher) UpdateDeviceIdentitySlot(ctx context.Context, input services.UpdateDeviceIdentitySlotInput) (output *models.Device, err error) {
	prev, err := mw.GetDeviceByID(ctx, services.GetDeviceByIDInput{
		ID: input.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get Device %s: %w", input.ID, err)
	}
	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(context.Background(), models.EventUpdateDeviceIDSlotKey, models.UpdateModel[models.Device]{
				Updated:  *output,
				Previous: *prev,
			})
		}
	}()
	return mw.next.UpdateDeviceIdentitySlot(ctx, input)
}

func (mw *deviceEventPublisher) UpdateDeviceMetadata(ctx context.Context, input services.UpdateDeviceMetadataInput) (output *models.Device, err error) {
	prev, err := mw.GetDeviceByID(ctx, services.GetDeviceByIDInput{
		ID: input.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get Device %s: %w", input.ID, err)
	}

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.EventUpdateDeviceMetadataKey, models.UpdateModel[models.Device]{
				Updated:  *output,
				Previous: *prev,
			})
		}
	}()
	return mw.next.UpdateDeviceMetadata(ctx, input)
}
