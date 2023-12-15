package amqppub

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/lamassuiot/lamassuiot/pkg/v3/messaging"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
)

type amqpEventPublisher struct {
	next           services.DMSManagerService
	eventPublisher *messaging.AMQPSetup
}

const dmsSource = "lamassuiot.dms-manager"

func NewDMSAmqpEventPublisher(amqpPublisher *messaging.AMQPSetup) services.DMSManagerMiddleware {
	return func(next services.DMSManagerService) services.DMSManagerService {
		return &amqpEventPublisher{
			next:           next,
			eventPublisher: amqpPublisher,
		}
	}
}

func (mw amqpEventPublisher) GetDMSStats(ctx context.Context, input services.GetDMSStatsInput) (*models.DMSStats, error) {
	return mw.next.GetDMSStats(ctx, input)
}

func (mw amqpEventPublisher) CreateDMS(ctx context.Context, input services.CreateDMSInput) (output *models.DMS, err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent(ctx, models.EventCreateDMSKey, output)
		}
	}()
	return mw.next.CreateDMS(ctx, input)
}

func (mw amqpEventPublisher) UpdateDMS(ctx context.Context, input services.UpdateDMSInput) (output *models.DMS, err error) {
	prev, err := mw.GetDMSByID(ctx, services.GetDMSByIDInput{
		ID: input.DMS.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("mw error: could not get DMS %s: %w", input.DMS.ID, err)
	}
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent(ctx, models.EventUpdateDMSMetadataKey, models.UpdateModel[models.DMS]{
				Previous: *prev,
				Updated:  *output,
			})
		}
	}()
	return mw.next.UpdateDMS(ctx, input)
}

func (mw amqpEventPublisher) GetDMSByID(ctx context.Context, input services.GetDMSByIDInput) (*models.DMS, error) {
	return mw.next.GetDMSByID(ctx, input)
}

func (mw amqpEventPublisher) GetAll(ctx context.Context, input services.GetAllInput) (string, error) {
	return mw.next.GetAll(ctx, input)
}

func (mw amqpEventPublisher) CACerts(aps string) ([]*x509.Certificate, error) {
	return mw.next.CACerts(aps)
}

func (mw amqpEventPublisher) Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (out *x509.Certificate, err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent(ctx, models.EventEnrollKey, models.EnrollReenrollEvent{
				Certificate: (*models.X509Certificate)(out),
				APS:         aps,
			})
		}
	}()
	return mw.next.Enroll(ctx, csr, aps)
}

func (mw amqpEventPublisher) Reenroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (out *x509.Certificate, err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent(ctx, models.EventReEnrollKey, models.EnrollReenrollEvent{
				Certificate: (*models.X509Certificate)(out),
				APS:         aps,
			})
		}
	}()
	return mw.next.Reenroll(ctx, csr, aps)
}

func (mw amqpEventPublisher) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, interface{}, error) {
	return mw.next.ServerKeyGen(ctx, csr, aps)
}

func (mw amqpEventPublisher) BindIdentityToDevice(ctx context.Context, input services.BindIdentityToDeviceInput) (output *models.BindIdentityToDeviceOutput, err error) {
	defer func() {
		if err == nil {
			mw.eventPublisher.PublishCloudEvent(ctx, models.EventBindDeviceIdentityKey, output)
		}
	}()
	return mw.next.BindIdentityToDevice(ctx, input)
}
