package amqppub

import (
	"context"
	"fmt"

	"github.com/lamassuiot/lamassuiot/v2/pkg/messaging"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
)

type amqpDeviceEventPublisher struct {
	next           services.DeviceManagerService
	eventPublisher *messaging.AMQPSetup
}

func NewDeviceAmqpEventPublisher(amqpPublisher *messaging.AMQPSetup) services.DeviceMiddleware {
	return func(next services.DeviceManagerService) services.DeviceManagerService {
		return &amqpDeviceEventPublisher{
			next:           next,
			eventPublisher: amqpPublisher,
		}
	}
}

func (mw *amqpDeviceEventPublisher) GetDevicesStats(input services.GetDevicesStatsInput) (*models.DevicesStats, error) {
	return mw.next.GetDevicesStats(input)
}

func (mw *amqpDeviceEventPublisher) CreateDevice(input services.CreateDeviceInput) (output *models.Device, err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent(context.Background(), models.EventCreateDeviceKey, output)
		}
	}()
	return mw.next.CreateDevice(input)
}

func (mw *amqpDeviceEventPublisher) GetDeviceByID(input services.GetDeviceByIDInput) (*models.Device, error) {
	return mw.next.GetDeviceByID(input)
}

func (mw *amqpDeviceEventPublisher) GetDevices(input services.GetDevicesInput) (string, error) {
	return mw.next.GetDevices(input)
}

func (mw *amqpDeviceEventPublisher) GetDeviceByDMS(input services.GetDevicesByDMSInput) (string, error) {
	return mw.next.GetDeviceByDMS(input)
}

func (mw *amqpDeviceEventPublisher) UpdateDeviceStatus(input services.UpdateDeviceStatusInput) (output *models.Device, err error) {
	prev, err := mw.GetDeviceByID(services.GetDeviceByIDInput{
		ID: input.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get Device %s: %w", input.ID, err)
	}

	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent(context.Background(), models.EventUpdateDeviceStatusKey, models.UpdateModel[models.Device]{
				Updated:  *output,
				Previous: *prev,
			})
		}
	}()
	return mw.next.UpdateDeviceStatus(input)
}

func (mw *amqpDeviceEventPublisher) UpdateDeviceIdentitySlot(input services.UpdateDeviceIdentitySlotInput) (output *models.Device, err error) {
	prev, err := mw.GetDeviceByID(services.GetDeviceByIDInput{
		ID: input.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get Device %s: %w", input.ID, err)
	}
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent(context.Background(), models.EventUpdateDeviceIDSlotKey, models.UpdateModel[models.Device]{
				Updated:  *output,
				Previous: *prev,
			})
		}
	}()
	return mw.next.UpdateDeviceIdentitySlot(input)
}

func (mw *amqpDeviceEventPublisher) UpdateDeviceMetadata(input services.UpdateDeviceMetadataInput) (output *models.Device, err error) {
	prev, err := mw.GetDeviceByID(services.GetDeviceByIDInput{
		ID: input.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get Device %s: %w", input.ID, err)
	}

	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent(context.Background(), models.EventUpdateDeviceMetadataKey, models.UpdateModel[models.Device]{
				Updated:  *output,
				Previous: *prev,
			})
		}
	}()
	return mw.next.UpdateDeviceMetadata(input)
}
