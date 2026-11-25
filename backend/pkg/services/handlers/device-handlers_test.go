package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"testing"

	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
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

// certWithCN builds a certificate whose CommonName is cn, with the given serial number and metadata.
func certWithCN(t *testing.T, cn, sn string, metadata map[string]any) models.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	x509Cert, err := chelpers.GenerateSelfSignedCertificate(key, cn)
	require.NoError(t, err)
	return models.Certificate{
		SerialNumber: sn,
		Subject:      models.Subject{CommonName: cn},
		Certificate:  (*models.X509Certificate)(x509Cert),
		Metadata:     metadata,
	}
}

func certUpdateEvent(t *testing.T, previous, updated models.Certificate) *event.Event {
	t.Helper()
	e := event.New()
	require.NoError(t, e.SetData(event.ApplicationJSON, models.UpdateModel[models.Certificate]{Previous: previous, Updated: updated}))
	return &e
}

func discardLogger() *logrus.Entry {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return logrus.NewEntry(logger)
}

// deviceManagerMock knows only the device dev; looking up any other device fails as it would in the device manager.
func deviceManagerMock(dev *models.Device) *svcmock.MockDeviceManagerService {
	svc := &svcmock.MockDeviceManagerService{}
	svc.On("GetDeviceByID", mock.Anything, services.GetDeviceByIDInput{ID: dev.ID}).Return(dev, nil)
	svc.On("GetDeviceByID", mock.Anything, mock.Anything).Return((*models.Device)(nil), errs.ErrDeviceNotFound)
	svc.On("UpdateDeviceIdentitySlot", mock.Anything, mock.Anything).Return(dev, nil)
	return svc
}

func activeDevice(id, sn string) *models.Device {
	return &models.Device{ID: id, IdentitySlot: &models.Slot[string]{Status: models.SlotActive, Secrets: map[int]string{0: sn}}}
}

func attachedTo(deviceID string) map[string]any {
	return map[string]any{"authorized_by": map[string]any{"ra_id": "dms-1"}, "device_id": deviceID}
}

func renewalWindowTriggered(triggered bool) []map[string]any {
	return []map[string]any{{"name": "Preventive", "delta": "3m", "triggered": triggered}}
}

func slotUpdatedTo(id string, status models.SlotStatus) any {
	return mock.MatchedBy(func(in services.UpdateDeviceIdentitySlotInput) bool {
		return in.ID == id && in.Slot.Status == status
	})
}

// The device is the one the DMS recorded when it bound the certificate, even when the certificate CommonName names
// something else.
func TestCertificateStatusHandlerFindsTheDeviceInTheBindingMetadata(t *testing.T) {
	cert := certWithCN(t, "ES", "sn-1", map[string]any{models.DMSAttachedToDeviceKey: attachedTo("dev-1")})
	cert.Status = models.StatusRevoked
	cert.RevocationReason = ocsp.Unspecified

	svc := deviceManagerMock(activeDevice("dev-1", "sn-1"))
	require.NoError(t, updateCertStatusHandler(context.Background(), certUpdateEvent(t, models.Certificate{}, cert), svc, discardLogger()))

	svc.AssertCalled(t, "UpdateDeviceIdentitySlot", mock.Anything, slotUpdatedTo("dev-1", models.SlotRevoke))
}

// A binding that recorded no device ID falls back to the certificate CommonName.
func TestCertificateStatusHandlerFallsBackToTheCommonName(t *testing.T) {
	cert := certWithCN(t, "dev-1", "sn-1", map[string]any{models.DMSAttachedToDeviceKey: map[string]any{}})
	cert.Status = models.StatusRevoked
	cert.RevocationReason = ocsp.Unspecified

	svc := deviceManagerMock(activeDevice("dev-1", "sn-1"))
	require.NoError(t, updateCertStatusHandler(context.Background(), certUpdateEvent(t, models.Certificate{}, cert), svc, discardLogger()))

	svc.AssertCalled(t, "UpdateDeviceIdentitySlot", mock.Anything, slotUpdatedTo("dev-1", models.SlotRevoke))
}

func TestCertificateMetadataHandlerFindsTheDeviceInTheBindingMetadata(t *testing.T) {
	previous := certWithCN(t, "ES", "sn-1", map[string]any{
		models.DMSAttachedToDeviceKey:                  attachedTo("dev-1"),
		models.CAMetadataMonitoringExpirationDeltasKey: renewalWindowTriggered(false),
	})
	updated := previous
	updated.Metadata = map[string]any{
		models.DMSAttachedToDeviceKey:                  attachedTo("dev-1"),
		models.CAMetadataMonitoringExpirationDeltasKey: renewalWindowTriggered(true),
	}

	svc := deviceManagerMock(activeDevice("dev-1", "sn-1"))
	require.NoError(t, updateCertMetaHandler(context.Background(), certUpdateEvent(t, previous, updated), svc, discardLogger()))

	svc.AssertCalled(t, "UpdateDeviceIdentitySlot", mock.Anything, slotUpdatedTo("dev-1", models.SlotRenewalWindow))
}

// A binding can name a device that has no identity slot: the device manager does not write the slot of a
// decommissioned device. There is no slot to sync, so the event is skipped.
func TestCertificateStatusHandlerSkipsADeviceWithoutSlot(t *testing.T) {
	cert := certWithCN(t, "ES", "sn-1", map[string]any{models.DMSAttachedToDeviceKey: attachedTo("dev-1")})
	cert.Status = models.StatusRevoked
	cert.RevocationReason = ocsp.Unspecified

	svc := deviceManagerMock(&models.Device{ID: "dev-1"})
	require.NotPanics(t, func() {
		require.NoError(t, updateCertStatusHandler(context.Background(), certUpdateEvent(t, models.Certificate{}, cert), svc, discardLogger()))
	})

	svc.AssertNotCalled(t, "UpdateDeviceIdentitySlot", mock.Anything, mock.Anything)
}

func TestCertificateMetadataHandlerSkipsADeviceWithoutSlot(t *testing.T) {
	previous := certWithCN(t, "ES", "sn-1", map[string]any{
		models.DMSAttachedToDeviceKey:                  attachedTo("dev-1"),
		models.CAMetadataMonitoringExpirationDeltasKey: renewalWindowTriggered(false),
	})
	updated := previous
	updated.Metadata = map[string]any{
		models.DMSAttachedToDeviceKey:                  attachedTo("dev-1"),
		models.CAMetadataMonitoringExpirationDeltasKey: renewalWindowTriggered(true),
	}

	svc := deviceManagerMock(&models.Device{ID: "dev-1"})
	require.NotPanics(t, func() {
		require.NoError(t, updateCertMetaHandler(context.Background(), certUpdateEvent(t, previous, updated), svc, discardLogger()))
	})

	svc.AssertNotCalled(t, "UpdateDeviceIdentitySlot", mock.Anything, mock.Anything)
}

// The binding key can hold a value the DMS did not write, since certificate metadata accepts any JSON patch. The
// handler then finds the device by the CommonName, as it did before it read the binding, instead of failing the event.
func TestCertificateMetadataHandlerFallsBackToTheCommonNameOnAnUnreadableBinding(t *testing.T) {
	previous := certWithCN(t, "dev-1", "sn-1", map[string]any{
		models.DMSAttachedToDeviceKey:                  "dms-1",
		models.CAMetadataMonitoringExpirationDeltasKey: renewalWindowTriggered(false),
	})
	updated := previous
	updated.Metadata = map[string]any{
		models.DMSAttachedToDeviceKey:                  "dms-1",
		models.CAMetadataMonitoringExpirationDeltasKey: renewalWindowTriggered(true),
	}

	svc := deviceManagerMock(activeDevice("dev-1", "sn-1"))
	require.NoError(t, updateCertMetaHandler(context.Background(), certUpdateEvent(t, previous, updated), svc, discardLogger()))

	svc.AssertCalled(t, "UpdateDeviceIdentitySlot", mock.Anything, slotUpdatedTo("dev-1", models.SlotRenewalWindow))
}

func TestCertificateMetadataHandlerFallsBackToTheCommonName(t *testing.T) {
	previous := certWithCN(t, "dev-1", "sn-1", map[string]any{
		models.CAMetadataMonitoringExpirationDeltasKey: renewalWindowTriggered(false),
	})
	updated := previous
	updated.Metadata = map[string]any{
		models.CAMetadataMonitoringExpirationDeltasKey: renewalWindowTriggered(true),
	}

	svc := deviceManagerMock(activeDevice("dev-1", "sn-1"))
	require.NoError(t, updateCertMetaHandler(context.Background(), certUpdateEvent(t, previous, updated), svc, discardLogger()))

	svc.AssertCalled(t, "UpdateDeviceIdentitySlot", mock.Anything, slotUpdatedTo("dev-1", models.SlotRenewalWindow))
}
