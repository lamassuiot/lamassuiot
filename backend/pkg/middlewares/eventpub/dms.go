package eventpub

import (
	"context"
	"crypto/x509"
	"fmt"

	lservices "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

type dmsEventPublisher struct {
	next       services.DMSManagerService
	eventMWPub ICloudEventPublisher
}

func NewDMSEventPublisher(eventMWPub ICloudEventPublisher) lservices.DMSManagerMiddleware {
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
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventCreateDMSKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("dms/%s", input.ID))

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, output)
		}
	}()
	return mw.next.CreateDMS(ctx, input)
}

func (mw dmsEventPublisher) UpdateDMS(ctx context.Context, input services.UpdateDMSInput) (output *models.DMS, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventUpdateDMSKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("dms/%s", input.DMS.ID))

	prev, err := mw.GetDMSByID(ctx, services.GetDMSByIDInput{
		ID: input.DMS.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get DMS %s: %w", input.DMS.ID, err)
	}
	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.UpdateModel[models.DMS]{
				Previous: *prev,
				Updated:  *output,
			})
		}
	}()
	return mw.next.UpdateDMS(ctx, input)
}

func (mw dmsEventPublisher) UpdateDMSMetadata(ctx context.Context, input services.UpdateDMSMetadataInput) (output *models.DMS, err error) {
	prev, err := mw.GetDMSByID(ctx, services.GetDMSByIDInput{
		ID: input.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get DMS %s: %w", input.ID, err)
	}

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.EventUpdateDMSMetadataKey, models.UpdateModel[models.DMS]{
				Updated:  *output,
				Previous: *prev,
			})
		}
	}()
	return mw.next.UpdateDMSMetadata(ctx, input)
}

func (mw dmsEventPublisher) DeleteDMS(ctx context.Context, input services.DeleteDMSInput) (err error) {
	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.EventDeleteDMSKey, input)
		}
	}()
	return mw.next.DeleteDMS(ctx, input)
}

func (mw dmsEventPublisher) GetDMSByID(ctx context.Context, input services.GetDMSByIDInput) (*models.DMS, error) {
	return mw.next.GetDMSByID(ctx, input)
}

func (mw dmsEventPublisher) GetAll(ctx context.Context, input services.GetAllInput) (string, error) {
	return mw.next.GetAll(ctx, input)
}

func (mw dmsEventPublisher) CACerts(ctx context.Context, aps string) ([]*x509.Certificate, error) {
	return mw.next.CACerts(ctx, aps)
}

func (mw dmsEventPublisher) Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (out *x509.Certificate, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventEnrollKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("dms/%s", aps))

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.EnrollReenrollEvent{
				Certificate: (*models.X509Certificate)(out),
				APS:         aps,
			})
		}
	}()
	return mw.next.Enroll(ctx, csr, aps)
}

func (mw dmsEventPublisher) Reenroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (out *x509.Certificate, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventReEnrollKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("dms/%s", aps))

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, models.EnrollReenrollEvent{
				Certificate: (*models.X509Certificate)(out),
				APS:         aps,
			})
		}
	}()
	return mw.next.Reenroll(ctx, csr, aps)
}

func (mw dmsEventPublisher) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, interface{}, error) {
	return mw.next.ServerKeyGen(ctx, csr, aps)
}

func (mw dmsEventPublisher) BindIdentityToDevice(ctx context.Context, input services.BindIdentityToDeviceInput) (output *models.BindIdentityToDeviceOutput, err error) {
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, models.EventBindDeviceIdentityKey)
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventSubject, fmt.Sprintf("device/%s", input.DeviceID))

	defer func() {
		if err == nil {
			mw.eventMWPub.PublishCloudEvent(ctx, output)
		}
	}()
	return mw.next.BindIdentityToDevice(ctx, input)
}
