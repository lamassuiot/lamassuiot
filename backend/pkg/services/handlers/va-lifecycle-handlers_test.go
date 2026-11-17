package handlers

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	svcmock "github.com/lamassuiot/lamassuiot/v4/core/pkg/services/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/ocsp"
)

const (
	subCAID    = "ca-sub"
	parentCAID = "ca-parent"
)

// subordinateCA is ca-sub, issued by ca-parent, in the given status.
func subordinateCA(status models.CertificateStatus, reason int) models.CACertificate {
	return models.CACertificate{ID: subCAID, Certificate: models.Certificate{
		SerialNumber: "sub-serial", Status: status, RevocationReason: models.RevocationReason(reason),
		IssuerCAMetadata: models.IssuerCAMetadata{ID: parentCAID},
	}}
}

func dispatch(t *testing.T, svc services.CRLService, eventType models.EventType, body any) error {
	t.Helper()
	e := event.New()
	e.SetType(string(eventType))
	assert.NoError(t, e.SetData(event.ApplicationJSON, body))
	h := NewVAEventHandler(helpers.SetupLogger("debug", "VA", "Test"), svc)
	handler, ok := h.DispatchMap[string(eventType)]
	if !assert.True(t, ok, "VA must handle %s events", eventType) {
		return nil
	}
	return handler(context.Background(), &e)
}

func caStatusUpdate(previous, updated models.CACertificate) models.UpdateModel[models.CACertificate] {
	return models.UpdateModel[models.CACertificate]{Previous: previous, Updated: updated}
}

func reconciled(caID string, status models.CRLSettingsStatus) *models.CRLSettings {
	return &models.CRLSettings{CAID: caID, Status: status}
}

func issuerSettings(status models.CRLSettingsStatus, regenerate bool) *models.CRLSettings {
	s := reconciled(parentCAID, status)
	s.Options.RegenerateOnRevoke = regenerate
	return s
}

func TestUpdateCAStatusHandlerReconcilesTheCA(t *testing.T) {
	root := subordinateCA(models.StatusRevoked, ocsp.KeyCompromise)
	root.Certificate.IssuerCAMetadata.ID = subCAID // self-signed: no issuer CRL to regenerate
	svc := new(svcmock.MockVAService)
	svc.On("ReconcileCRLSettings", mock.Anything, services.ReconcileCRLSettingsInput{CAID: subCAID}).Return(reconciled(subCAID, models.CRLSettingsFinal), nil)

	err := dispatch(t, svc, models.EventUpdateCAStatusKey, caStatusUpdate(subordinateCA(models.StatusActive, 0), root))

	assert.NoError(t, err)
	svc.AssertExpectations(t)
	svc.AssertNotCalled(t, "GetCRLSettings", mock.Anything, mock.Anything)
	svc.AssertNotCalled(t, "CalculateCRL", mock.Anything, mock.Anything)
}

func TestUpdateCAStatusHandlerWithoutSettingsIsAccepted(t *testing.T) {
	ca := subordinateCA(models.StatusExpired, 0)
	svc := new(svcmock.MockVAService)
	svc.On("ReconcileCRLSettings", mock.Anything, mock.Anything).Return(nil, errs.ErrCRLSettingsNotFound)

	assert.NoError(t, dispatch(t, svc, models.EventUpdateCAStatusKey, caStatusUpdate(subordinateCA(models.StatusActive, 0), ca)))
}

func TestUpdateCAStatusHandlerReturnsReconcileErrors(t *testing.T) {
	failure := errors.New("bucket down")
	svc := new(svcmock.MockVAService)
	svc.On("ReconcileCRLSettings", mock.Anything, mock.Anything).Return(nil, failure)

	err := dispatch(t, svc, models.EventUpdateCAStatusKey, caStatusUpdate(subordinateCA(models.StatusActive, 0), subordinateCA(models.StatusRevoked, ocsp.KeyCompromise)))
	assert.ErrorIs(t, err, failure, "the event is retried")
}

// UpdateCAStatus publishes no certificate.status.update for the certificate of the CA itself, so the CRL of its issuer
// is regenerated here.
func TestUpdateCAStatusHandlerRegeneratesTheIssuerCRL(t *testing.T) {
	for _, tc := range []struct {
		name               string
		previous, updated  models.CACertificate
		issuer             *models.CRLSettings
		issuerErr          error
		wantIssuerCRL      bool
		wantIssuerSettings bool
	}{
		{name: "revoked", previous: subordinateCA(models.StatusActive, 0), updated: subordinateCA(models.StatusRevoked, ocsp.KeyCompromise),
			issuer: issuerSettings(models.CRLSettingsActive, true), wantIssuerSettings: true, wantIssuerCRL: true},
		{name: "on hold", previous: subordinateCA(models.StatusActive, 0), updated: subordinateCA(models.StatusRevoked, ocsp.CertificateHold),
			issuer: issuerSettings(models.CRLSettingsActive, true), wantIssuerSettings: true, wantIssuerCRL: true},
		{name: "reactivated from hold", previous: subordinateCA(models.StatusRevoked, ocsp.CertificateHold), updated: subordinateCA(models.StatusActive, 0),
			issuer: issuerSettings(models.CRLSettingsActive, true), wantIssuerSettings: true, wantIssuerCRL: true},
		{name: "expired", previous: subordinateCA(models.StatusActive, 0), updated: subordinateCA(models.StatusExpired, 0)},
		{name: "issuer final", previous: subordinateCA(models.StatusActive, 0), updated: subordinateCA(models.StatusRevoked, ocsp.KeyCompromise),
			issuer: issuerSettings(models.CRLSettingsFinal, true), wantIssuerSettings: true},
		{name: "issuer does not regenerate on revoke", previous: subordinateCA(models.StatusActive, 0), updated: subordinateCA(models.StatusRevoked, ocsp.KeyCompromise),
			issuer: issuerSettings(models.CRLSettingsActive, false), wantIssuerSettings: true},
		{name: "issuer without settings", previous: subordinateCA(models.StatusActive, 0), updated: subordinateCA(models.StatusRevoked, ocsp.KeyCompromise),
			issuerErr: errs.ErrCRLSettingsNotFound, wantIssuerSettings: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := new(svcmock.MockVAService)
			svc.On("ReconcileCRLSettings", mock.Anything, services.ReconcileCRLSettingsInput{CAID: subCAID}).Return(reconciled(subCAID, models.CRLSettingsActive), nil)
			if tc.wantIssuerSettings {
				svc.On("GetCRLSettings", mock.Anything, services.GetCRLSettingsInput{CAID: parentCAID}).Return(tc.issuer, tc.issuerErr)
			}
			if tc.wantIssuerCRL {
				svc.On("CalculateCRL", mock.Anything, services.CalculateCRLInput{CAID: parentCAID}).Return(&x509.RevocationList{}, nil)
			}

			assert.NoError(t, dispatch(t, svc, models.EventUpdateCAStatusKey, caStatusUpdate(tc.previous, tc.updated)))
			svc.AssertExpectations(t)
			if !tc.wantIssuerCRL {
				svc.AssertNotCalled(t, "CalculateCRL", mock.Anything, mock.Anything)
			}
			if !tc.wantIssuerSettings {
				svc.AssertNotCalled(t, "GetCRLSettings", mock.Anything, mock.Anything)
			}
		})
	}
}

// The deleted CA is checked rather than taken from the event: reconciling archives the settings only once it is gone.
func TestDeleteCAHandlerReconcilesTheSettings(t *testing.T) {
	svc := new(svcmock.MockVAService)
	svc.On("ReconcileCRLSettings", mock.Anything, services.ReconcileCRLSettingsInput{CAID: subCAID}).Return(reconciled(subCAID, models.CRLSettingsArchived), nil)

	assert.NoError(t, dispatch(t, svc, models.EventDeleteCAKey, services.DeleteCAInput{CAID: subCAID}))
	svc.AssertExpectations(t)
}

func TestDeleteCAHandlerWithoutSettingsIsAccepted(t *testing.T) {
	svc := new(svcmock.MockVAService)
	svc.On("ReconcileCRLSettings", mock.Anything, mock.Anything).Return(nil, errs.ErrCRLSettingsNotFound)

	assert.NoError(t, dispatch(t, svc, models.EventDeleteCAKey, services.DeleteCAInput{CAID: subCAID}))
}
