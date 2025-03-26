package eventpub

import (
	"context"
	"fmt"

	lservices "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

type dmsEventPublisher struct {
	next       services.DMSManagerService
	eventMWPub ICloudEventMiddlewarePublisher
}

func NewDMSEventPublisher(eventMWPub ICloudEventMiddlewarePublisher) lservices.DMSManagerMiddleware {
	return func(next services.DMSManagerService) services.DMSManagerService {
		return &dmsEventPublisher{
			next:       next,
			eventMWPub: eventMWPub,
		}
	}
}

func (mw dmsEventPublisher) GetDMSStats(ctx context.Context, input services.GetDMSStatsInput) (*models.DMSStats, error) {
	return mw.next.GetDMSStats(ctx, input)
}

func (mw dmsEventPublisher) CreateDMS(ctx context.Context, input services.CreateDMSInput) (output *models.DMS, err error) {
	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.EventCreateDMSKey, output)
		}
	}()
	return mw.next.CreateDMS(ctx, input)
}

func (mw dmsEventPublisher) UpdateDMS(ctx context.Context, input services.UpdateDMSInput) (output *models.DMS, err error) {
	prev, err := mw.GetDMSByID(ctx, services.GetDMSByIDInput{
		ID: input.DMS.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get DMS %s: %w", input.DMS.ID, err)
	}
	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.EventUpdateDMSKey, models.UpdateModel[models.DMS]{
				Previous: *prev,
				Updated:  *output,
			})
		}
	}()
	return mw.next.UpdateDMS(ctx, input)
}

func (mw dmsEventPublisher) GetDMSByID(ctx context.Context, input services.GetDMSByIDInput) (*models.DMS, error) {
	return mw.next.GetDMSByID(ctx, input)
}

func (mw dmsEventPublisher) GetAll(ctx context.Context, input services.GetAllInput) (string, error) {
	return mw.next.GetAll(ctx, input)
}

func (mw dmsEventPublisher) BindIdentityToDevice(ctx context.Context, input services.BindIdentityToDeviceInput) (output *models.BindIdentityToDeviceOutput, err error) {
	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.EventBindDeviceIdentityKey, output)
		}
	}()
	return mw.next.BindIdentityToDevice(ctx, input)
}
