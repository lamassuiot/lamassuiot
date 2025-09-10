package auditpub

import (
	"context"
	"crypto/x509"

	lservices "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

type DmsAuditEventPublisher struct {
	next     services.DMSManagerService
	auditPub AuditPublisher
}

func NewDmsAuditEventPublisher(auditPub AuditPublisher) lservices.DMSManagerMiddleware {
	return func(next services.DMSManagerService) services.DMSManagerService {
		return &DmsAuditEventPublisher{
			next:     next,
			auditPub: auditPub,
		}
	}
}

func (mw DmsAuditEventPublisher) GetDMSStats(ctx context.Context, input services.GetDMSStatsInput) (*models.DMSStats, error) {
	return mw.next.GetDMSStats(ctx, input)
}

func (mw DmsAuditEventPublisher) CreateDMS(ctx context.Context, input services.CreateDMSInput) (output *models.DMS, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventCreateDMSKey, input, err, output)
	}()

	return mw.next.CreateDMS(ctx, input)
}

func (mw DmsAuditEventPublisher) UpdateDMS(ctx context.Context, input services.UpdateDMSInput) (output *models.DMS, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventUpdateDMSKey, input, err, output)
	}()

	return mw.next.UpdateDMS(ctx, input)
}

func (mw DmsAuditEventPublisher) GetDMSByID(ctx context.Context, input services.GetDMSByIDInput) (*models.DMS, error) {
	return mw.next.GetDMSByID(ctx, input)
}

func (mw DmsAuditEventPublisher) GetAll(ctx context.Context, input services.GetAllInput) (string, error) {
	return mw.next.GetAll(ctx, input)
}

func (mw DmsAuditEventPublisher) CACerts(ctx context.Context, aps string) ([]*x509.Certificate, error) {
	return mw.next.CACerts(ctx, aps)
}

func (mw DmsAuditEventPublisher) Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (out *x509.Certificate, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventEnrollKey, map[string]interface{}{
			"csr": csr,
			"aps": aps,
		}, err, (*models.X509Certificate)(out))
	}()

	return mw.next.Enroll(ctx, csr, aps)
}

func (mw DmsAuditEventPublisher) Reenroll(ctx context.Context, csr *x509.CertificateRequest, aps string) (out *x509.Certificate, err error) {
	//TODO: check if this is correct
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventReEnrollKey, map[string]interface{}{
			"csr": csr,
			"aps": aps,
		}, err, (*models.X509Certificate)(out))
	}()

	return mw.next.Reenroll(ctx, csr, aps)
}

func (mw DmsAuditEventPublisher) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string) (*x509.Certificate, interface{}, error) {
	return mw.next.ServerKeyGen(ctx, csr, aps)
}

func (mw DmsAuditEventPublisher) BindIdentityToDevice(ctx context.Context, input services.BindIdentityToDeviceInput) (output *models.BindIdentityToDeviceOutput, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventBindDeviceIdentityKey, input, err, output)
	}()

	return mw.next.BindIdentityToDevice(ctx, input)
}

func (mw DmsAuditEventPublisher) UpdateDMSMetadata(ctx context.Context, input services.UpdateDMSMetadataInput) (output *models.DMS, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventUpdateDMSMetadataKey, input, err, output)
	}()

	return mw.next.UpdateDMSMetadata(ctx, input)
}

func (mw DmsAuditEventPublisher) DeleteDMS(ctx context.Context, input services.DeleteDMSInput) (err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventDeleteDMSKey, input, err, nil)
	}()

	return mw.next.DeleteDMS(ctx, input)
}
