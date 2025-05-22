package eventpub

import (
	"context"
	"crypto/x509"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/services/ra"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

type estRAEventPublisher struct {
	next       services.ESTService
	eventMWPub ICloudEventMiddlewarePublisher
}

func NewESTRAEventPublisher(eventMWPub ICloudEventMiddlewarePublisher) ra.ESTMiddleware {
	return func(next services.ESTService) services.ESTService {
		return &estRAEventPublisher{
			next:       next,
			eventMWPub: eventMWPub,
		}
	}
}

func (mw estRAEventPublisher) CACerts(ctx context.Context, aps string) ([]*x509.Certificate, error) {
	return mw.next.CACerts(ctx, aps)
}

func (mw estRAEventPublisher) Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (out *x509.Certificate, err error) {
	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.EventEnrollKey, models.EnrollReenrollEvent{
				Certificate: (*models.X509Certificate)(out),
				APS:         aps,
			})
		}
	}()
	return mw.next.Enroll(ctx, csr, aps)
}

func (mw estRAEventPublisher) Reenroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (out *x509.Certificate, err error) {
	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.EventReEnrollKey, models.EnrollReenrollEvent{
				Certificate: (*models.X509Certificate)(out),
				APS:         aps,
			})
		}
	}()
	return mw.next.Reenroll(ctx, csr, aps)
}

func (mw estRAEventPublisher) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, interface{}, error) {
	return mw.next.ServerKeyGen(ctx, csr, aps)
}
