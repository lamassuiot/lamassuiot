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

func (mw *clrEventPublisher) CalculateCRL(ctx context.Context, input services.CalculateCRLInput) (output *x509.RevocationList, err error) {
	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(context.Background(), models.EventCreateCRL, output)
		}
	}()
	return mw.next.CalculateCRL(ctx, input)
}
