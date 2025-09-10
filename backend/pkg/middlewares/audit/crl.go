package auditpub

import (
	"context"
	"crypto/x509"

	beService "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

type CRLAuditEventPublisher struct {
	next     services.CRLService
	auditPub AuditPublisher
}

func NewCRLAuditEventPublisher(audit AuditPublisher) beService.CRLMiddleware {
	return func(next services.CRLService) services.CRLService {
		return &CRLAuditEventPublisher{
			next:     next,
			auditPub: audit,
		}
	}
}

func (mw *CRLAuditEventPublisher) GetCRL(ctx context.Context, input services.GetCRLInput) (output *x509.RevocationList, err error) {
	return mw.next.GetCRL(ctx, input)
}

func (mw *CRLAuditEventPublisher) GetVARole(ctx context.Context, input services.GetVARoleInput) (output *models.VARole, err error) {
	return mw.next.GetVARole(ctx, input)
}

func (mw *CRLAuditEventPublisher) GetVARoles(ctx context.Context, input services.GetVARolesInput) (string, error) {
	return mw.next.GetVARoles(ctx, input)
}

func (mw *CRLAuditEventPublisher) UpdateVARole(ctx context.Context, input services.UpdateVARoleInput) (output *models.VARole, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventUpdateVARole, input, err, output)
	}()

	return mw.next.UpdateVARole(ctx, input)
}

func (mw *CRLAuditEventPublisher) CalculateCRL(ctx context.Context, input services.CalculateCRLInput) (output *x509.RevocationList, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventCreateCRL, input, err, output)
	}()

	return mw.next.CalculateCRL(ctx, input)
}

func (mw *CRLAuditEventPublisher) InitCRLRole(ctx context.Context, caSKI string) (output *models.VARole, err error) {
	defer func() {
		mw.auditPub.HandleServiceOutputAndPublishAuditRecord(ctx, models.EventInitCRLRole, caSKI, err, output)
	}()

	return mw.next.InitCRLRole(ctx, caSKI)
}
