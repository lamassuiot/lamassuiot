package jobs

import (
	"context"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/robfig/cron/v3"
	"github.com/sirupsen/logrus"
)

type VACrlMonitor struct {
	logger    *logrus.Entry
	service   services.CRLService
	frequency string
}

func NewVACrlMonitorJob(service services.CRLService, frequency string, logger *logrus.Entry) *VACrlMonitor {
	return &VACrlMonitor{
		service:   service,
		logger:    logger,
		frequency: frequency,
	}
}

func (svc *VACrlMonitor) Run() {
	ctx := helpers.InitContext()
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	now := time.Now()
	lFunc.Info("starting periodic VA CRL check")

	nextScheduledRun, err := cron.ParseStandard(svc.frequency)
	if err != nil {
		lFunc.Errorf("could not parse frequency %s: %s", svc.frequency, err)
		return
	}

	nextRunTime := nextScheduledRun.Next(now)
	nextRunTimeDelta := nextRunTime.Sub(now)

	svc.service.GetVARoles(ctx, services.GetVARolesInput{
		QueryParameters: &resources.QueryParameters{},
		ExhaustiveRun:   true,
		ApplyFunc: func(v models.VARole) {
			lFunc.Infof("checking VA Role %s", v.CAID)
			// Check if CRL is still valid
			if v.LatestCRL.ValidUntil.Before(now) {
				// CRL is not valid anymore, calculate new CRL
				lFunc.Infof("CRL for CA %s expired at %s (%s)", v.CAID, v.LatestCRL.ValidUntil, v.LatestCRL.ValidUntil.Sub(now))
				_, err := svc.service.CalculateCRL(context.Background(), services.CalculateCRLInput{
					CAID: v.CAID,
				})
				if err != nil {
					lFunc.Warnf("something went wrong while calculating CRL for CA %s: %s", v.CAID, err)
				}
			} else {
				// CRL is still valid
				if v.LatestCRL.ValidUntil.Before(nextRunTime) {
					// CRL will expire before the next check
					delay := now.Sub(v.LatestCRL.ValidFrom.Add(time.Duration(v.CRLOptions.RefreshInterval)))
					lFunc.Warnf("CRL for CA %s will expire in %s which is before next check at %s (%s)", v.CAID, delay, nextRunTime, nextRunTimeDelta)
				} else {
					lFunc.Infof("CRL for CA %s is valid until %s (%s)", v.CAID, v.LatestCRL.ValidUntil, v.LatestCRL.ValidUntil.Sub(now))
				}
			}
		},
	})

	end := time.Now()
	lFunc.Infof("ending check. Took %v", end.Sub(now))
}
