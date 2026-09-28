package jobs

import (
	"context"
	"time"

	"github.com/google/uuid"
	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

type VACrlMonitor struct {
	logger       *logrus.Entry
	service      services.CRLService
	tenantLister storage.ActiveTenantLister
	blindPeriod  time.Duration
}

func NewVACrlMonitorJob(logger *logrus.Entry, service services.CRLService, blindPeriod time.Duration) *VACrlMonitor {
	return &VACrlMonitor{
		service:     service,
		logger:      logger,
		blindPeriod: blindPeriod,
	}
}

func (svc *VACrlMonitor) SetTenantLister(tenantLister storage.ActiveTenantLister) {
	svc.tenantLister = tenantLister
}

func (svc *VACrlMonitor) Run() {
	ctx := helpers.InitContext()
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)
	lFunc.Info("starting periodic VA CRL check")
	if svc.tenantLister == nil {
		lFunc.Error("cannot run tenant-scoped CRL monitoring without an active tenant lister")
		return
	}
	tenants, err := svc.tenantLister.ListActiveTenants(ctx)
	if err != nil {
		lFunc.Errorf("could not list active tenants for CRL monitoring: %s", err)
		return
	}
	for _, tenant := range tenants {
		if tenant.ID == "" || tenant.OrganizationID == "" || tenant.Status != models.TenantActive {
			lFunc.Errorf("skipping active tenant record with invalid identity or status")
			continue
		}
		tenantContext := core.WithTenantContext(ctx, core.TenantContext{
			OrganizationID: tenant.OrganizationID,
			TenantID:       tenant.ID,
			ActorID:        "va-crl-monitor",
			ActorType:      "system",
			CorrelationID:  uuid.NewString(),
			Source:         "va-crl-monitor",
			TenantStatus:   tenant.Status,
			Validated:      true,
		})
		svc.processVARoles(tenantContext, lFunc)
	}
}

func (svc *VACrlMonitor) processVARoles(ctx context.Context, lFunc *logrus.Entry) {
	now := time.Now()
	svc.service.GetVARoles(ctx, services.GetVARolesInput{
		QueryParameters: &resources.QueryParameters{},
		ExhaustiveRun:   true,
		ApplyFunc: func(v models.VARole) {
			lFunc.Infof("checking VA Role %s", v.CASubjectKeyID)
			// Check if CRL is still valid
			crlRemainDuration := v.LatestCRL.ValidUntil.Sub(now)

			if crlRemainDuration < svc.blindPeriod {
				// CRL is not valid anymore or will expire during the validityWindow, calculate new CRL
				lFunc.Infof("CRL for CA %s expired at %s (%s)", v.CASubjectKeyID, v.LatestCRL.ValidUntil, v.LatestCRL.ValidUntil.Sub(now))
				input := services.CalculateCRLInput{
					CASubjectKeyID: v.CASubjectKeyID,
				}

				_, err := svc.service.CalculateCRL(ctx, input)
				if err != nil {
					lFunc.Warnf("something went wrong while calculating CRL for CA %s: %s", v.CASubjectKeyID, err)
				}
			} else {
				lFunc.Infof("CRL for CA %s is valid until %s (%s)", v.CASubjectKeyID, v.LatestCRL.ValidUntil, v.LatestCRL.ValidUntil.Sub(now))
			}
		},
	})
}
