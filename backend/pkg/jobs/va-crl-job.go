package jobs

import (
	"context"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
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
	ctx := helpers.InitContext()
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)
	lFunc.Info("starting periodic VA CRL check")
	svc.processVARoles(ctx, lFunc)
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

				_, err := svc.service.CalculateCRL(context.Background(), input)
				if err != nil {
					lFunc.Warnf("something went wrong while calculating CRL for CA %s: %s", v.CASubjectKeyID, err)
				}
			} else {
				lFunc.Infof("CRL for CA %s is valid until %s (%s)", v.CASubjectKeyID, v.LatestCRL.ValidUntil, v.LatestCRL.ValidUntil.Sub(now))
			}
		},
	})
}
