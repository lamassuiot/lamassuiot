package eventpub

import (
	"context"
	"crypto/x509"
	"fmt"

	beService "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/eventpublisher"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

type clrEventPublisher struct {
	next       services.CRLService
	eventMWPub eventpublisher.ICloudEventPublisher
}

func NewCRLEventPublisher(eventMWPub eventpublisher.ICloudEventPublisher) beService.CRLMiddleware {
	return func(next services.CRLService) services.CRLService {
		return &clrEventPublisher{
			next:       next,
			eventMWPub: eventpublisher.NewEventPublisherWithSourceMiddleware(eventMWPub, models.VASource),
		}
	}
}

func (mw *clrEventPublisher) GetCRL(ctx context.Context, input services.GetCRLInput) (output *x509.RevocationList, err error) {
	return mw.next.GetCRL(ctx, input)
}

func (mw *clrEventPublisher) GetVARole(ctx context.Context, input services.GetVARoleInput) (output *models.VARole, err error) {
	return mw.next.GetVARole(ctx, input)
}

func (mw *clrEventPublisher) GetVARoles(ctx context.Context, input services.GetVARolesInput) (string, error) {
	return mw.next.GetVARoles(ctx, input)
}

func (mw *clrEventPublisher) UpdateVARole(ctx context.Context, input services.UpdateVARoleInput) (output *models.VARole, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventUpdateVARole)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("crl/%s", input.CASubjectKeyID))

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, output)
		}
	}()
	return mw.next.UpdateVARole(ctx, input)
}

func (mw *clrEventPublisher) CalculateCRL(ctx context.Context, input services.CalculateCRLInput) (output *x509.RevocationList, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventCreateCRL)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("crl/%s", input.CASubjectKeyID))

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, output)
		}
	}()
	return mw.next.CalculateCRL(ctx, input)
}

func (mw *clrEventPublisher) InitCRLRole(ctx context.Context, caSki string) (output *models.VARole, err error) {
	return mw.next.InitCRLRole(ctx, caSki)
}
