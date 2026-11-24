package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"testing"

	"github.com/cloudevents/sdk-go/v2/event"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	svcmock "github.com/lamassuiot/lamassuiot/v4/core/pkg/services/mock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

// The handler only syncs the slot with the status its certificate already has. If it did not say so, the update would
// re-revoke the certificate that a CA hold put on hold, with Unspecified, and delete the mark that releasing the CA
// looks for: the release would no longer reinstate the device.
func TestCertificateStatusHandlerOnlySyncsTheSlotWithTheCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	x509Cert, err := chelpers.GenerateSelfSignedCertificate(key, "dev-1")
	require.NoError(t, err)

	cert := models.Certificate{
		SerialNumber: "sn-1", Status: models.StatusRevoked, RevocationReason: ocsp.CertificateHold,
		Certificate: (*models.X509Certificate)(x509Cert),
		Metadata:    map[string]any{models.DMSAttachedToDeviceKey: map[string]any{"device_id": "dev-1"}},
	}
	e := event.New()
	require.NoError(t, e.SetData(event.ApplicationJSON, models.UpdateModel[models.Certificate]{Updated: cert}))

	device := &models.Device{ID: "dev-1", IdentitySlot: &models.Slot[string]{
		Status: models.SlotActive, Secrets: map[int]string{0: "sn-1"},
	}}
	svc := &svcmock.MockDeviceManagerService{}
	svc.On("GetDeviceByID", mock.Anything, services.GetDeviceByIDInput{ID: "dev-1"}).Return(device, nil)
	svc.On("UpdateDeviceIdentitySlot", mock.Anything, mock.Anything).Return(device, nil)

	logger := logrus.New()
	logger.SetOutput(io.Discard)
	require.NoError(t, updateCertStatusHandler(context.Background(), &e, svc, logrus.NewEntry(logger)))

	svc.AssertCalled(t, "UpdateDeviceIdentitySlot", mock.Anything, mock.MatchedBy(func(in services.UpdateDeviceIdentitySlotInput) bool {
		return in.ID == "dev-1" && in.Slot.Status == models.SlotRevoke && in.SyncCertificateStatus
	}))
}
