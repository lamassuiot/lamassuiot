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
