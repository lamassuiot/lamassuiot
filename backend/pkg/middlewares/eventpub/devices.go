package eventpub

import (
	"context"
	"fmt"

	lservices "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

type deviceEventPublisher struct {
	next       services.DeviceManagerService
	eventMWPub ICloudEventPublisher
}

func NewDeviceEventPublisher(eventMWPub ICloudEventPublisher) lservices.DeviceMiddleware {
	return func(next services.DeviceManagerService) services.DeviceManagerService {
		return &deviceEventPublisher{
			next:       next,
			eventMWPub: NewEventPublisherWithSourceMiddleware(eventMWPub, models.DeviceManagerSource),
		}
	}
}

func (mw *deviceEventPublisher) GetDevicesStats(ctx context.Context, input services.GetDevicesStatsInput) (*models.DevicesStats, error) {
	return mw.next.GetDevicesStats(ctx, input)
}

func (mw *deviceEventPublisher) CreateDevice(ctx context.Context, input services.CreateDeviceInput) (output *models.Device, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventCreateDeviceKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("device/%s", input.ID))

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(context.Background(), output)
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
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventUpdateDeviceStatusKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("device/%s", input.ID))

	prev, err := mw.GetDeviceByID(ctx, services.GetDeviceByIDInput{
		ID: input.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get Device %s: %w", input.ID, err)
	}

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.UpdateModel[models.Device]{
				Updated:  *output,
				Previous: *prev,
			})
		}
	}()
	return mw.next.UpdateDeviceStatus(ctx, input)
}

func (mw *deviceEventPublisher) UpdateDeviceIdentitySlot(ctx context.Context, input services.UpdateDeviceIdentitySlotInput) (output *models.Device, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventUpdateDeviceIDSlotKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("device/%s", input.ID))

	prev, err := mw.GetDeviceByID(ctx, services.GetDeviceByIDInput{
		ID: input.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get Device %s: %w", input.ID, err)
	}
	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.UpdateModel[models.Device]{
				Updated:  *output,
				Previous: *prev,
			})
		}
	}()
	return mw.next.UpdateDeviceIdentitySlot(ctx, input)
}

func (mw *deviceEventPublisher) UpdateDeviceMetadata(ctx context.Context, input services.UpdateDeviceMetadataInput) (output *models.Device, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventUpdateDeviceMetadataKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("device/%s", input.ID))

	prev, err := mw.GetDeviceByID(ctx, services.GetDeviceByIDInput{
		ID: input.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get Device %s: %w", input.ID, err)
	}

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.UpdateModel[models.Device]{
				Updated:  *output,
				Previous: *prev,
			})
		}
	}()
	return mw.next.UpdateDeviceMetadata(ctx, input)
}

func (mw *deviceEventPublisher) DeleteDevice(ctx context.Context, input services.DeleteDeviceInput) (err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventDeleteDeviceKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("device/%s", input.ID))

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, input)
		}
	}()
	return mw.next.DeleteDevice(ctx, input)
}

func (mw *deviceEventPublisher) CreateDeviceEvent(ctx context.Context, input services.CreateDeviceEventInput) (output *models.DeviceEvent, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventDeleteDeviceKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("device/%s", input.Event.DeviceID))

	defer func() {
		mw.eventMWPub.PublishCloudEvent(ctx, input)
	}()

	return mw.next.CreateDeviceEvent(ctx, input)
}

func (mw *deviceEventPublisher) GetDeviceEvents(ctx context.Context, input services.GetDeviceEventsInput) (string, error) {
	return mw.next.GetDeviceEvents(ctx, input)
}
