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
	svc.service.GetCRLSettingsList(ctx, services.GetCRLSettingsListInput{
		QueryParameters: &resources.QueryParameters{},
		ExhaustiveRun:   true,
		ApplyFunc: func(v models.CRLSettings) {
			if v.Status != models.CRLSettingsActive {
				// Archived settings keep serving their last CRL, but nothing signs a new one.
				return
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
				input := services.CalculateCRLInput{
					CAID: v.CAID,
				}

				_, err := svc.service.CalculateCRL(context.Background(), input)
				if err != nil {
					lFunc.Warnf("something went wrong while calculating CRL for CA %s: %s", v.CAID, err)
				}
			} else {
				lFunc.Infof("CRL for CA %s is valid until %s (%s)", v.CAID, v.LatestCRL.ValidUntil, v.LatestCRL.ValidUntil.Sub(now))
			}
		},
	})
}
