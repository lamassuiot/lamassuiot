package auditpub

import (
	"context"
	"crypto/x509"

	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/middlewares/eventpub"
	beService "github.com/lamassuiot/lamassuiot/v4/backend/pkg/services"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
)

type CRLAuditEventPublisher struct {
	next     services.CRLService
	auditPub AuditPublisher
}

func NewCRLAuditEventPublisher(audit AuditPublisher) beService.CRLMiddleware {
	return func(next services.CRLService) services.CRLService {
		return &CRLAuditEventPublisher{
			next: next,
			auditPub: AuditPublisher{
				ICloudEventPublisher: eventpub.NewEventPublisherWithSourceMiddleware(audit, models.VASource),
			},
		}
	}
}

func (mw *CRLAuditEventPublisher) GetCRL(ctx context.Context, input services.GetCRLInput) (output *x509.RevocationList, err error) {
	return mw.next.GetCRL(ctx, input)
}

func (mw *CRLAuditEventPublisher) GetCRLSettings(ctx context.Context, input services.GetCRLSettingsInput) (output *models.CRLSettings, err error) {
	return mw.next.GetCRLSettings(ctx, input)
}

func (mw *CRLAuditEventPublisher) GetCRLSettingsList(ctx context.Context, input services.GetCRLSettingsListInput) (string, error) {
	return mw.next.GetCRLSettingsList(ctx, input)
}

func (mw *CRLAuditEventPublisher) UpdateCRLSettings(ctx context.Context, input services.UpdateCRLSettingsInput) (output *models.CRLSettings, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventUpdateCRLSettings, input, err, output)
	}()

	return mw.next.UpdateCRLSettings(ctx, input)
}

func (mw *CRLAuditEventPublisher) CalculateCRL(ctx context.Context, input services.CalculateCRLInput) (output *x509.RevocationList, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventCreateCRL, input, err, output)
	}()

	return mw.next.CalculateCRL(ctx, input)
}

func (mw *CRLAuditEventPublisher) InitCRLSettings(ctx context.Context, caID string) (output *models.CRLSettings, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventInitCRLSettings, caID, err, output)
	}()

	return mw.next.InitCRLSettings(ctx, caID)
}

func (mw *CRLAuditEventPublisher) FinalizeCRLSettings(ctx context.Context, input services.FinalizeCRLSettingsInput) (output *models.CRLSettings, finalCRL *x509.RevocationList, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventFinalizeCRLSettings, input, err, output)
	}()

	return mw.next.FinalizeCRLSettings(ctx, input)
}

func (mw *CRLAuditEventPublisher) ArchiveCRLSettings(ctx context.Context, input services.ArchiveCRLSettingsInput) (output *models.CRLSettings, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventArchiveCRLSettings, input, err, output)
	}()

	return mw.next.ArchiveCRLSettings(ctx, input)
}

func (mw *CRLAuditEventPublisher) DeleteCRLSettings(ctx context.Context, input services.DeleteCRLSettingsInput) (err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventDeleteCRLSettings, input, err, nil)
	}()

	return mw.next.DeleteCRLSettings(ctx, input)
}

// ReconcileCRLSettings records nothing of its own: the changes it makes go through FinalizeCRLSettings and
// ArchiveCRLSettings, which are audited.
func (mw *CRLAuditEventPublisher) ReconcileCRLSettings(ctx context.Context, input services.ReconcileCRLSettingsInput) (*models.CRLSettings, error) {
	return mw.next.ReconcileCRLSettings(ctx, input)
}
