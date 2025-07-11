package eventpub

import (
	"context"
	"crypto/x509"

	beService "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

type clrEventPublisher struct {
	next       services.CRLService
	eventMWPub ICloudEventMiddlewarePublisher
}

func NewCRLEventPublisher(eventMWPub ICloudEventMiddlewarePublisher) beService.CRLMiddleware {
	return func(next services.CRLService) services.CRLService {
		return &clrEventPublisher{
			next:       next,
			eventMWPub: eventMWPub,
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
	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(context.Background(), models.EventUpdateVARole, output)
		}
	}()
	return mw.next.UpdateVARole(ctx, input)
}

func (mw *clrEventPublisher) CalculateCRL(ctx context.Context, input services.CalculateCRLInput) (output *x509.RevocationList, err error) {
	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(context.Background(), models.EventCreateCRL, output)
		}
	}()
	return mw.next.CalculateCRL(ctx, input)
}

func (mw *clrEventPublisher) InitCRLRole(ctx context.Context, caSki string) (output *models.VARole, err error) {
	return mw.next.InitCRLRole(ctx, caSki)
}
