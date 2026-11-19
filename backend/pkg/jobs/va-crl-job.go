package jobs

import (
	"context"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/sirupsen/logrus"
)

// reconcileRevocationGrace is how long the monitor leaves a revoked CA to the ca.status.update event before issuing its
// final CRL itself: until UpdateCAStatus has revoked every certificate of the CA, a final CRL would miss some.
const reconcileRevocationGrace = time.Hour

type VACrlMonitor struct {
	logger      *logrus.Entry
	service     services.CRLService
	blindPeriod time.Duration
}

func NewVACrlMonitorJob(logger *logrus.Entry, service services.CRLService, blindPeriod time.Duration) *VACrlMonitor {
	return &VACrlMonitor{
		service:     service,
		logger:      logger,
		blindPeriod: blindPeriod,
	}
}

func (svc *VACrlMonitor) Run() {
	ctx := helpers.InitJobContext("va-crl-monitor")
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)
	lFunc.Info("starting periodic VA CRL check")
	svc.processCRLSettings(ctx, lFunc)
}

func (svc *VACrlMonitor) processCRLSettings(ctx context.Context, lFunc *logrus.Entry) {
	now := time.Now()

	// Collected first: reconciling changes the rows being listed.
	pending := []models.CRLSettings{}
	_, err := svc.service.GetCRLSettingsList(ctx, services.GetCRLSettingsListInput{
		QueryParameters: &resources.QueryParameters{},
		ExhaustiveRun:   true,
		ApplyFunc: func(v models.CRLSettings) {
			// Archived settings keep serving their last CRL, but nothing changes them anymore.
			if v.Status != models.CRLSettingsArchived {
				pending = append(pending, v)
			}
		},
	})
	if err != nil {
		lFunc.Errorf("could not list CRL settings: %s", err)
	}

	for _, listed := range pending {
		// Events may have been lost, and migrated settings of revoked or expired CAs start ACTIVE: bring them in line
		// with their CA first.
		v, err := svc.service.ReconcileCRLSettings(ctx, services.ReconcileCRLSettingsInput{CAID: listed.CAID, RevokedBefore: now.Add(-reconcileRevocationGrace)})
		if err != nil {
			lFunc.Warnf("could not reconcile CRL settings of CA %s with its CA: %s", listed.CAID, err)
			continue
		}
		if v.Status != models.CRLSettingsActive {
			continue
		}

		lFunc.Infof("checking CRL settings of CA %s", v.CAID)
		// Check if CRL is still valid
		crlRemainDuration := v.LatestCRL.ValidUntil.Sub(now)
		refreshInterval := time.Duration(v.Options.RefreshInterval)
		refreshDue := refreshInterval > 0 && now.Sub(v.LatestCRL.ValidFrom) >= refreshInterval

		if crlRemainDuration < svc.blindPeriod || refreshDue {
			// CRL is not valid anymore, will expire during the blind period, or its refresh interval has elapsed: calculate new CRL
			if refreshDue {
				lFunc.Infof("CRL for CA %s issued at %s reached its refresh interval (%s)", v.CAID, v.LatestCRL.ValidFrom, v.Options.RefreshInterval)
			} else {
				lFunc.Infof("CRL for CA %s expired at %s (%s)", v.CAID, v.LatestCRL.ValidUntil, v.LatestCRL.ValidUntil.Sub(now))
			}

			_, err := svc.service.CalculateCRL(ctx, services.CalculateCRLInput{CAID: v.CAID})
			if err != nil {
				lFunc.Warnf("something went wrong while calculating CRL for CA %s: %s", v.CAID, err)
			}
		} else {
			lFunc.Infof("CRL for CA %s is valid until %s (%s)", v.CAID, v.LatestCRL.ValidUntil, v.LatestCRL.ValidUntil.Sub(now))
		}
	}
}
