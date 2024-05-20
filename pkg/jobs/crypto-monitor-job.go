package jobs

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"slices"
	"time"

	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
	"github.com/sirupsen/logrus"
)

type CryptoMonitor struct {
	logger  *logrus.Entry
	service services.CAService
}

func NewCryptoMonitor(service services.CAService, logger *logrus.Entry) *CryptoMonitor {
	return &CryptoMonitor{
		service: service,
		logger:  logger,
	}
}

func (svc *CryptoMonitor) Run() {
	ctx := helpers.InitContext()
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	now := time.Now()
	lFunc.Info("starting periodic CAs and Certificate check for expired certificates")

	svc.scanCAsForUpdate(ctx, now)
	svc.scanCertificatesForUpdate(ctx, now)

	end := time.Now()
	lFunc.Infof("ending check. Took %v", end.Sub(now))
}

func (svc *CryptoMonitor) scanCertificatesForUpdate(ctx context.Context, now time.Time) {
	updateCertificateIfNeededAdapter := func(cert models.Certificate) {
		svc.updateCertificateIfNeeded(cert, now, ctx)
	}

	svc.service.GetCertificatesByStatus(ctx, services.GetCertificatesByStatusInput{
		Status: models.StatusActive,
		ListInput: resources.ListInput[models.Certificate]{
			QueryParameters: nil,
			ExhaustiveRun:   true,
			ApplyFunc:       updateCertificateIfNeededAdapter,
		},
	})
}

func (svc *CryptoMonitor) updateCertificateIfNeeded(cert models.Certificate, now time.Time, ctx context.Context) {

	//check if should be updated to expired
	if cert.ValidTo.Before(now) {
		svc.service.UpdateCertificateStatus(ctx, services.UpdateCertificateStatusInput{
			SerialNumber: cert.SerialNumber,
			NewStatus:    models.StatusExpired,
		})
		return
	}

	//check if meta contains additional monitoring deltas
	shouldUpdateMeta, newMetadata := svc.shouldUpdateMonitoringDeltas(cert.Metadata, x509.Certificate(*cert.Certificate))
	if shouldUpdateMeta {
		svc.service.UpdateCertificateMetadata(ctx, services.UpdateCertificateMetadataInput{
			SerialNumber: cert.SerialNumber,
			Metadata:     newMetadata,
		})
	}
}

func (svc *CryptoMonitor) scanCAsForUpdate(ctx context.Context, now time.Time) {

	caScanFuncAdapter := func(ca models.CACertificate) {
		svc.updateCAIfNeeded(ca, now, ctx)
	}

	svc.service.GetCAs(ctx, services.GetCAsInput{
		QueryParameters: nil,
		ExhaustiveRun:   true,
		ApplyFunc:       caScanFuncAdapter,
	})
}

func (svc *CryptoMonitor) updateCAIfNeeded(ca models.CACertificate, now time.Time, ctx context.Context) {
	if ca.ValidTo.Before(now) && ca.Status == models.StatusActive {
		svc.service.UpdateCAStatus(ctx, services.UpdateCAStatusInput{
			CAID:   ca.ID,
			Status: models.StatusExpired,
		})
		return
	}

	shouldUpdateMeta, newMetadata := svc.shouldUpdateMonitoringDeltas(ca.Metadata, x509.Certificate(*ca.Certificate.Certificate))
	if shouldUpdateMeta {
		svc.service.UpdateCAMetadata(ctx, services.UpdateCAMetadataInput{
			CAID:     ca.ID,
			Metadata: newMetadata,
		})
	}
}

// checks if metadata has additional expiration intervals to be checked.
// returns
// - bool: true if metadata should be updated
// - updated metadata
func (svc *CryptoMonitor) shouldUpdateMonitoringDeltas(metadata map[string]any, certificate x509.Certificate) (bool, map[string]any) {
	if additionalDeltasIface, ok := metadata[models.CAMetadataMonitoringExpirationDeltasKey]; ok {
		//check if additionalDeltasIface is of type
		deltasB, err := json.Marshal(additionalDeltasIface)
		if err != nil {
			return false, map[string]any{}
		}

		var additionalDeltas models.CAMetadataMonitoringExpirationDeltas
		err = json.Unmarshal(deltasB, &additionalDeltas)
		if err == nil {
			orderedDeltas := additionalDeltas

			//order deltas from smallest to biggest
			slices.SortStableFunc(orderedDeltas, func(a models.MonitoringExpirationDelta, b models.MonitoringExpirationDelta) int {
				if a.Delta == b.Delta {
					return 0
				}
				if a.Delta < b.Delta {
					return -1
				} else {
					return 1
				}
			})

			newMeta := metadata
			updated := false
			for idx, additionalDelta := range orderedDeltas {
				if time.Now().After(certificate.NotAfter.Add(-time.Duration(additionalDelta.Delta))) {
					if !orderedDeltas[idx].Triggered {
						//switch 'trigger' monitoring delta to true
						orderedDeltas[idx].Triggered = true
						newMeta[models.CAMetadataMonitoringExpirationDeltasKey] = orderedDeltas
						updated = true
					}
				}
			}

			if updated {
				return true, newMeta
			} else {
				return false, map[string]any{}
			}
		}
	}

	return false, map[string]any{}
}
