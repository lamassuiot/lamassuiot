package handlers

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	svcmock "github.com/lamassuiot/lamassuiot/v4/core/pkg/services/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const (
	reissueTestCAID      = "ca-id"
	reissueTestSKI       = "shared-ski" // CAs sharing a key share it: no handler may route by it
	reissueTestOldSerial = "old-serial"
	reissueTestNewSerial = "new-serial"
)

func reissueEvent(t *testing.T) *event.Event {
	t.Helper()

	caWithSerial := func(sn string) models.CACertificate {
		return models.CACertificate{
			ID:                      reissueTestCAID,
			CertificateSerialNumber: sn,
			Certificate: models.Certificate{
				SerialNumber: sn,
				SubjectKeyID: reissueTestSKI,
			},
		}
	}

	e := event.New()
	e.SetType(string(models.EventReissueCAKey))
	err := e.SetData(event.ApplicationJSON, models.UpdateModel[models.CACertificate]{
		Previous: caWithSerial(reissueTestOldSerial),
		Updated:  caWithSerial(reissueTestNewSerial),
	})
	assert.NoError(t, err)

	return &e
}

func settingsWithSigner(serial string) *models.CRLSettings {
	return &models.CRLSettings{
		CAID:   reissueTestCAID,
		Status: models.CRLSettingsActive,
		Options: models.CRLSettingsOptions{
			RefreshInterval:    models.TimeDuration(24 * time.Hour),
			Validity:           models.TimeDuration(48 * time.Hour),
			SignerSerialNumber: serial,
			RegenerateOnRevoke: true,
		},
	}
}

func archivedSettings() *models.CRLSettings {
	s := settingsWithSigner("")
	s.Status = models.CRLSettingsArchived
	return s
}

func dispatchReissue(t *testing.T, svc services.CRLService) error {
	t.Helper()

	h := NewVAEventHandler(helpers.SetupLogger("debug", "VA", "Test"), svc)
	handler, ok := h.DispatchMap[string(models.EventReissueCAKey)]
	if !assert.True(t, ok, "VA must handle %s events", models.EventReissueCAKey) {
		return nil
	}

	return handler(context.Background(), reissueEvent(t))
}

func TestReissueCAHandlerRotatesSignerFromPreviousCertificate(t *testing.T) {
	svc := new(svcmock.MockVAService)
	settings := settingsWithSigner(reissueTestOldSerial)

	expectedOptions := settings.Options
	expectedOptions.SignerSerialNumber = reissueTestNewSerial

	svc.On("GetCRLSettings", mock.Anything, services.GetCRLSettingsInput{CAID: reissueTestCAID}).Return(settings, nil)
	svc.On("UpdateCRLSettings", mock.Anything, services.UpdateCRLSettingsInput{CAID: reissueTestCAID, Options: expectedOptions}).Return(settingsWithSigner(reissueTestNewSerial), nil)
	svc.On("CalculateCRL", mock.Anything, services.CalculateCRLInput{CAID: reissueTestCAID}).Return(&x509.RevocationList{}, nil)

	err := dispatchReissue(t, svc)

	assert.NoError(t, err)
	svc.AssertExpectations(t)
}

func TestReissueCAHandlerKeepsSignerThatIsNotThePreviousCertificate(t *testing.T) {
	svc := new(svcmock.MockVAService)

	svc.On("GetCRLSettings", mock.Anything, services.GetCRLSettingsInput{CAID: reissueTestCAID}).Return(settingsWithSigner("other-serial"), nil)

	err := dispatchReissue(t, svc)

	assert.NoError(t, err)
	svc.AssertNotCalled(t, "UpdateCRLSettings", mock.Anything, mock.Anything)
	svc.AssertNotCalled(t, "CalculateCRL", mock.Anything, mock.Anything)
}

// A retry of a reissue event whose CRL generation failed finds the signer already moved: it must still regenerate
// the CRL, or the event is acknowledged while the VA keeps serving the CRL signed by the superseded certificate.
func TestReissueCAHandlerRegeneratesCRLWhenSignerAlreadyMoved(t *testing.T) {
	svc := new(svcmock.MockVAService)

	svc.On("GetCRLSettings", mock.Anything, services.GetCRLSettingsInput{CAID: reissueTestCAID}).Return(settingsWithSigner(reissueTestNewSerial), nil)
	svc.On("CalculateCRL", mock.Anything, services.CalculateCRLInput{CAID: reissueTestCAID}).Return(&x509.RevocationList{}, nil)

	err := dispatchReissue(t, svc)

	assert.NoError(t, err)
	svc.AssertExpectations(t)
	svc.AssertNotCalled(t, "UpdateCRLSettings", mock.Anything, mock.Anything)
}

func TestReissueCAHandlerReturnsCRLGenerationError(t *testing.T) {
	svc := new(svcmock.MockVAService)
	crlErr := errors.New("bucket down")

	svc.On("GetCRLSettings", mock.Anything, services.GetCRLSettingsInput{CAID: reissueTestCAID}).Return(settingsWithSigner(reissueTestOldSerial), nil)
	svc.On("UpdateCRLSettings", mock.Anything, mock.Anything).Return(settingsWithSigner(reissueTestNewSerial), nil)
	svc.On("CalculateCRL", mock.Anything, services.CalculateCRLInput{CAID: reissueTestCAID}).Return((*x509.RevocationList)(nil), crlErr)

	err := dispatchReissue(t, svc)

	assert.ErrorIs(t, err, crlErr)
}

func TestReissueCAHandlerKeepsSignerWhenNewCertificateIsRejected(t *testing.T) {
	svc := new(svcmock.MockVAService)

	svc.On("GetCRLSettings", mock.Anything, services.GetCRLSettingsInput{CAID: reissueTestCAID}).Return(settingsWithSigner(reissueTestOldSerial), nil)
	svc.On("UpdateCRLSettings", mock.Anything, mock.Anything).Return((*models.CRLSettings)(nil), errs.ErrValidateBadRequest)

	err := dispatchReissue(t, svc)

	assert.NoError(t, err)
	svc.AssertExpectations(t)
	svc.AssertNotCalled(t, "CalculateCRL", mock.Anything, mock.Anything)
}

func TestReissueCAHandlerIgnoresCAWithoutCRLSettings(t *testing.T) {
	svc := new(svcmock.MockVAService)

	svc.On("GetCRLSettings", mock.Anything, services.GetCRLSettingsInput{CAID: reissueTestCAID}).Return((*models.CRLSettings)(nil), errs.ErrCRLSettingsNotFound)

	err := dispatchReissue(t, svc)

	assert.NoError(t, err)
	svc.AssertNotCalled(t, "UpdateCRLSettings", mock.Anything, mock.Anything)
	svc.AssertNotCalled(t, "CalculateCRL", mock.Anything, mock.Anything)
}

func revokedCertificateEvent(t *testing.T) *event.Event {
	t.Helper()

	crt, _, err := helpers.GenerateSelfSignedCA(x509.ECDSA, time.Hour, "revoked-cert")
	assert.NoError(t, err)

	certWithStatus := func(status models.CertificateStatus) models.Certificate {
		return models.Certificate{
			SerialNumber:     "cert-serial",
			SubjectKeyID:     "cert-ski",
			AuthorityKeyID:   reissueTestSKI,
			IssuerCAMetadata: models.IssuerCAMetadata{ID: reissueTestCAID},
			Status:           status,
			Certificate:      (*models.X509Certificate)(crt),
		}
	}

	e := event.New()
	e.SetType(string(models.EventUpdateCertificateStatusKey))
	err = e.SetData(event.ApplicationJSON, models.UpdateModel[models.Certificate]{
		Previous: certWithStatus(models.StatusActive),
		Updated:  certWithStatus(models.StatusRevoked),
	})
	assert.NoError(t, err)

	return &e
}

func dispatchRevocation(t *testing.T, svc services.CRLService) error {
	t.Helper()

	h := NewVAEventHandler(helpers.SetupLogger("debug", "VA", "Test"), svc)
	handler, ok := h.DispatchMap[string(models.EventUpdateCertificateStatusKey)]
	if !assert.True(t, ok, "VA must handle %s events", models.EventUpdateCertificateStatusKey) {
		return nil
	}

	return handler(context.Background(), revokedCertificateEvent(t))
}

func TestRevocationHandlerRegeneratesCRLOfIssuerCA(t *testing.T) {
	svc := new(svcmock.MockVAService)

	svc.On("GetCRLSettings", mock.Anything, services.GetCRLSettingsInput{CAID: reissueTestCAID}).Return(settingsWithSigner(reissueTestOldSerial), nil)
	svc.On("CalculateCRL", mock.Anything, services.CalculateCRLInput{CAID: reissueTestCAID}).Return(&x509.RevocationList{}, nil)

	err := dispatchRevocation(t, svc)

	assert.NoError(t, err)
	svc.AssertExpectations(t)
}

// An issuer CA without a VA role has no CRL to regenerate. Failing the event would make the event bus retry it
// (2s + 6s + 10s) while holding back every later certificate event, and the retries cannot succeed.
func TestRevocationHandlerIgnoresIssuerCAWithoutCRLSettings(t *testing.T) {
	svc := new(svcmock.MockVAService)

	svc.On("GetCRLSettings", mock.Anything, services.GetCRLSettingsInput{CAID: reissueTestCAID}).Return((*models.CRLSettings)(nil), errs.ErrCRLSettingsNotFound)

	err := dispatchRevocation(t, svc)

	assert.NoError(t, err)
	svc.AssertNotCalled(t, "CalculateCRL", mock.Anything, mock.Anything)
}

func TestRevocationHandlerReturnsUnexpectedGetSettingsError(t *testing.T) {
	svc := new(svcmock.MockVAService)
	getErr := errors.New("storage down")

	svc.On("GetCRLSettings", mock.Anything, services.GetCRLSettingsInput{CAID: reissueTestCAID}).Return((*models.CRLSettings)(nil), getErr)

	err := dispatchRevocation(t, svc)

	assert.Error(t, err, "other errors must still be retried by the event bus")
	svc.AssertNotCalled(t, "CalculateCRL", mock.Anything, mock.Anything)
}

func TestReissueCAHandlerReturnsUnexpectedUpdateError(t *testing.T) {
	svc := new(svcmock.MockVAService)
	updateErr := errors.New("storage down")

	svc.On("GetCRLSettings", mock.Anything, services.GetCRLSettingsInput{CAID: reissueTestCAID}).Return(settingsWithSigner(reissueTestOldSerial), nil)
	svc.On("UpdateCRLSettings", mock.Anything, mock.Anything).Return((*models.CRLSettings)(nil), updateErr)

	err := dispatchReissue(t, svc)

	assert.ErrorIs(t, err, updateErr)
	svc.AssertNotCalled(t, "CalculateCRL", mock.Anything, mock.Anything)
}

// The revocation of a certificate goes to the CRL of the CA that issued it, not to whichever CA shares its AKI.
func TestRevocationHandlerRoutesByIssuerCAIDNotByAKI(t *testing.T) {
	svc := new(svcmock.MockVAService)

	svc.On("GetCRLSettings", mock.Anything, services.GetCRLSettingsInput{CAID: reissueTestCAID}).Return(settingsWithSigner(reissueTestOldSerial), nil)
	svc.On("CalculateCRL", mock.Anything, services.CalculateCRLInput{CAID: reissueTestCAID}).Return(&x509.RevocationList{}, nil)

	assert.NoError(t, dispatchRevocation(t, svc))
	svc.AssertNotCalled(t, "GetCRLSettings", mock.Anything, services.GetCRLSettingsInput{CAID: reissueTestSKI})
	svc.AssertExpectations(t)
}

func TestRevocationHandlerIgnoresNonActiveSettings(t *testing.T) {
	svc := new(svcmock.MockVAService)

	svc.On("GetCRLSettings", mock.Anything, mock.Anything).Return(archivedSettings(), nil)

	assert.NoError(t, dispatchRevocation(t, svc))
	svc.AssertNotCalled(t, "CalculateCRL", mock.Anything, mock.Anything)
}

func TestRevocationHandlerSkipsRegenerationWhenDisabled(t *testing.T) {
	svc := new(svcmock.MockVAService)
	settings := settingsWithSigner(reissueTestOldSerial)
	settings.Options.RegenerateOnRevoke = false

	svc.On("GetCRLSettings", mock.Anything, mock.Anything).Return(settings, nil)

	assert.NoError(t, dispatchRevocation(t, svc))
	svc.AssertNotCalled(t, "CalculateCRL", mock.Anything, mock.Anything)
}

func TestReissueCAHandlerIgnoresNonActiveSettings(t *testing.T) {
	svc := new(svcmock.MockVAService)

	svc.On("GetCRLSettings", mock.Anything, mock.Anything).Return(archivedSettings(), nil)

	assert.NoError(t, dispatchReissue(t, svc))
	svc.AssertNotCalled(t, "UpdateCRLSettings", mock.Anything, mock.Anything)
	svc.AssertNotCalled(t, "CalculateCRL", mock.Anything, mock.Anything)
}

func TestCreateCAHandlerInitsSettingsByCAID(t *testing.T) {
	svc := new(svcmock.MockVAService)
	svc.On("InitCRLSettings", mock.Anything, reissueTestCAID).Return(settingsWithSigner("sn"), nil)

	e := event.New()
	e.SetType(string(models.EventCreateCAKey))
	assert.NoError(t, e.SetData(event.ApplicationJSON, models.CACertificate{
		ID: reissueTestCAID, Certificate: models.Certificate{SubjectKeyID: reissueTestSKI},
	}))

	handler := NewVAEventHandler(helpers.SetupLogger("debug", "VA", "Test"), svc).DispatchMap[string(models.EventCreateCAKey)]
	assert.NoError(t, handler(context.Background(), &e))
	svc.AssertExpectations(t)
}
