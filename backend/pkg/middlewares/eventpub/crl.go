package eventpub

import (
	"context"
	"crypto/x509"
	"fmt"

	beService "github.com/lamassuiot/lamassuiot/v4/backend/pkg/services"
	"github.com/lamassuiot/lamassuiot/v4/core"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
)

type clrEventPublisher struct {
	next       services.CRLService
	eventMWPub ICloudEventPublisher
}

func NewCRLEventPublisher(eventMWPub ICloudEventPublisher) beService.CRLMiddleware {
	return func(next services.CRLService) services.CRLService {
		return &clrEventPublisher{
			next:       next,
			eventMWPub: NewEventPublisherWithSourceMiddleware(eventMWPub, models.VASource),
		}
	}
}

func (mw *clrEventPublisher) GetCRL(ctx context.Context, input services.GetCRLInput) (output *x509.RevocationList, err error) {
	return mw.next.GetCRL(ctx, input)
}

func (mw *clrEventPublisher) GetCRLSettings(ctx context.Context, input services.GetCRLSettingsInput) (output *models.CRLSettings, err error) {
	return mw.next.GetCRLSettings(ctx, input)
}

func (mw *clrEventPublisher) GetCRLSettingsList(ctx context.Context, input services.GetCRLSettingsListInput) (string, error) {
	return mw.next.GetCRLSettingsList(ctx, input)
}

func (mw *clrEventPublisher) UpdateCRLSettings(ctx context.Context, input services.UpdateCRLSettingsInput) (output *models.CRLSettings, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventUpdateCRLSettings)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("crl/%s", input.CAID))

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, output)
		}
	}()
	return mw.next.UpdateCRLSettings(ctx, input)
}

func (mw *clrEventPublisher) CalculateCRL(ctx context.Context, input services.CalculateCRLInput) (output *x509.RevocationList, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventCreateCRL)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("crl/%s", input.CAID))

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, output)
		}
	}()
	return mw.next.CalculateCRL(ctx, input)
}

func (mw *clrEventPublisher) InitCRLSettings(ctx context.Context, caID string) (output *models.CRLSettings, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventInitCRLSettings)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("crl/%s", caID))

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, output)
		}
	}()
	return mw.next.InitCRLSettings(ctx, caID)
}
