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

// decommissionedDeviceMock returns a mock whose device "dev-1" is decommissioned with active certificate "sn-1", and
// whose slot writes fail as the device manager fails them for such a device.
func decommissionedDeviceMock() *svcmock.MockDeviceManagerService {
	device := &models.Device{ID: "dev-1", Status: models.DeviceDecommissioned, IdentitySlot: &models.Slot[string]{
		Status: models.SlotRevoke, Secrets: map[int]string{0: "sn-1"},
	}}
	svc := &svcmock.MockDeviceManagerService{}
	svc.On("GetDeviceByID", mock.Anything, services.GetDeviceByIDInput{ID: "dev-1"}).Return(device, nil)
	svc.On("UpdateDeviceIdentitySlot", mock.Anything, mock.Anything).Return((*models.Device)(nil), errs.ErrDeviceInvalidStatus)
	return svc
}

func discardLogger() *logrus.Entry {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return logrus.NewEntry(logger)
}

// Decommissioning a device revokes its certificate, and that revocation reaches this handler. The device is retired,
// so the event has nothing to sync: the handler must not fail on it.
func TestCertificateStatusHandlerSkipsDecommissionedDevices(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	x509Cert, err := chelpers.GenerateSelfSignedCertificate(key, "dev-1")
	require.NoError(t, err)

	cert := models.Certificate{
		SerialNumber: "sn-1", Status: models.StatusRevoked, RevocationReason: ocsp.CessationOfOperation,
		Certificate: (*models.X509Certificate)(x509Cert),
		Metadata:    map[string]any{models.DMSAttachedToDeviceKey: map[string]any{"device_id": "dev-1"}},
	}
	e := event.New()
	require.NoError(t, e.SetData(event.ApplicationJSON, models.UpdateModel[models.Certificate]{Updated: cert}))

	svc := decommissionedDeviceMock()
	require.NoError(t, updateCertStatusHandler(context.Background(), &e, svc, discardLogger()))
	svc.AssertNotCalled(t, "UpdateDeviceIdentitySlot", mock.Anything, mock.Anything)
}

// The expiration monitoring of the certificate of a decommissioned device has nothing to update on the device.
func TestCertificateMetadataHandlerSkipsDecommissionedDevices(t *testing.T) {
	deltas := func(triggered bool) map[string]any {
		return map[string]any{models.CAMetadataMonitoringExpirationDeltasKey: models.CAMetadataMonitoringExpirationDeltas{
			{Name: "Preventive", Triggered: triggered},
		}}
	}
	updated := models.Certificate{SerialNumber: "sn-1", Subject: models.Subject{CommonName: "dev-1"}, Metadata: deltas(true)}
	previous := models.Certificate{SerialNumber: "sn-1", Subject: models.Subject{CommonName: "dev-1"}, Metadata: deltas(false)}
	e := event.New()
	require.NoError(t, e.SetData(event.ApplicationJSON, models.UpdateModel[models.Certificate]{Updated: updated, Previous: previous}))

	svc := decommissionedDeviceMock()
	require.NoError(t, updateCertMetaHandler(context.Background(), &e, svc, discardLogger()))
	svc.AssertNotCalled(t, "UpdateDeviceIdentitySlot", mock.Anything, mock.Anything)
}

// monitoringDeltas returns certificate metadata whose Preventive and Critical expiration deltas are triggered as given.
func monitoringDeltas(preventive, critical bool) map[string]any {
	return map[string]any{
		models.DMSAttachedToDeviceKey: map[string]any{"device_id": "dev-1"},
		models.CAMetadataMonitoringExpirationDeltasKey: models.CAMetadataMonitoringExpirationDeltas{
			{Name: "Preventive", Triggered: preventive},
			{Name: "Critical", Triggered: critical},
		},
	}
}

// activeDeviceMock returns a mock whose device "dev-1" is active with certificate "sn-1" in a slot with status slot,
// and records the slot writes.
func activeDeviceMock(slot models.SlotStatus) *svcmock.MockDeviceManagerService {
	device := &models.Device{ID: "dev-1", Status: models.DeviceActive, IdentitySlot: &models.Slot[string]{
		Status: slot, Secrets: map[int]string{0: "sn-1"},
	}}
	svc := &svcmock.MockDeviceManagerService{}
	svc.On("GetDeviceByID", mock.Anything, services.GetDeviceByIDInput{ID: "dev-1"}).Return(device, nil)
	svc.On("UpdateDeviceIdentitySlot", mock.Anything, mock.Anything).Return(device, nil)
	return svc
}

// slotWrites returns the slot statuses the handler wrote, in order.
func slotWrites(svc *svcmock.MockDeviceManagerService) []models.SlotStatus {
	var statuses []models.SlotStatus
	for _, call := range svc.Calls {
		if call.Method == "UpdateDeviceIdentitySlot" {
			statuses = append(statuses, call.Arguments.Get(1).(services.UpdateDeviceIdentitySlotInput).Slot.Status)
		}
	}
	return statuses
}

func reactivationEvent(t *testing.T, preventive, critical bool) *event.Event {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	x509Cert, err := chelpers.GenerateSelfSignedCertificate(key, "dev-1")
	require.NoError(t, err)

	cert := models.Certificate{
		SerialNumber: "sn-1", Status: models.StatusActive,
		Certificate: (*models.X509Certificate)(x509Cert),
		Metadata:    monitoringDeltas(preventive, critical),
	}
	e := event.New()
	require.NoError(t, e.SetData(event.ApplicationJSON, models.UpdateModel[models.Certificate]{Updated: cert}))
	return &e
}

// Releasing a hold reactivates the certificate. The slot gets back the status its expiration deltas already reached:
// those deltas are triggered for good, so the monitoring would never report them again.
func TestReactivatedCertificateGetsTheStatusOfItsTriggeredDeltas(t *testing.T) {
	tests := []struct {
		name                 string
		preventive, critical bool
		expected             models.SlotStatus
	}{
		{name: "NoDeltaTriggered", expected: models.SlotActive},
		{name: "PreventiveTriggered", preventive: true, expected: models.SlotRenewalWindow},
		{name: "CriticalTriggered", preventive: true, critical: true, expected: models.SlotAboutToExpire},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := activeDeviceMock(models.SlotRevoke)
			require.NoError(t, updateCertStatusHandler(context.Background(), reactivationEvent(t, tc.preventive, tc.critical), svc, discardLogger()))

			require.Equal(t, []models.SlotStatus{tc.expected}, slotWrites(svc))
			svc.AssertCalled(t, "UpdateDeviceIdentitySlot", mock.Anything, mock.MatchedBy(func(in services.UpdateDeviceIdentitySlotInput) bool {
				return in.SyncCertificateStatus
			}))
		})
	}
}

func deltasEvent(t *testing.T, previousPreventive, previousCritical, preventive, critical bool) *event.Event {
	t.Helper()
	updated := models.Certificate{SerialNumber: "sn-1", Subject: models.Subject{CommonName: "dev-1"}, Metadata: monitoringDeltas(preventive, critical)}
	previous := models.Certificate{SerialNumber: "sn-1", Subject: models.Subject{CommonName: "dev-1"}, Metadata: monitoringDeltas(previousPreventive, previousCritical)}
	e := event.New()
	require.NoError(t, e.SetData(event.ApplicationJSON, models.UpdateModel[models.Certificate]{Updated: updated, Previous: previous}))
	return &e
}

// When both deltas trigger in the same pass of the monitoring (it was paused by a hold, or its period is longer than
// the gap between the deltas), the device ends in the most severe status.
func TestBothDeltasTriggeringAtOnceLeaveTheDeviceExpiringSoon(t *testing.T) {
	svc := activeDeviceMock(models.SlotActive)
	require.NoError(t, updateCertMetaHandler(context.Background(), deltasEvent(t, false, false, true, true), svc, discardLogger()))

	writes := slotWrites(svc)
	require.NotEmpty(t, writes)
	require.Equal(t, models.SlotAboutToExpire, writes[len(writes)-1])
	require.NotContains(t, writes, models.SlotRenewalWindow)
}

// A Preventive delta reported after the Critical one must not bring an expiring device back to the renewal window.
func TestPreventiveDeltaDoesNotDowngradeAnExpiringDevice(t *testing.T) {
	svc := activeDeviceMock(models.SlotAboutToExpire)
	require.NoError(t, updateCertMetaHandler(context.Background(), deltasEvent(t, false, true, true, true), svc, discardLogger()))

	require.NotContains(t, slotWrites(svc), models.SlotRenewalWindow)
}

// The usual path keeps working: each delta moves the device one step when it triggers.
func TestEachDeltaMovesTheDeviceWhenItTriggers(t *testing.T) {
	svc := activeDeviceMock(models.SlotActive)
	require.NoError(t, updateCertMetaHandler(context.Background(), deltasEvent(t, false, false, true, false), svc, discardLogger()))
	require.Equal(t, []models.SlotStatus{models.SlotRenewalWindow}, slotWrites(svc))

	svc = activeDeviceMock(models.SlotRenewalWindow)
	require.NoError(t, updateCertMetaHandler(context.Background(), deltasEvent(t, true, false, true, true), svc, discardLogger()))
	require.Equal(t, []models.SlotStatus{models.SlotAboutToExpire}, slotWrites(svc))
}

// A metadata change that triggers no delta leaves the slot alone.
func TestMetadataChangeWithoutNewDeltaLeavesTheSlot(t *testing.T) {
	svc := activeDeviceMock(models.SlotRenewalWindow)
	require.NoError(t, updateCertMetaHandler(context.Background(), deltasEvent(t, true, false, true, false), svc, discardLogger()))
	require.Empty(t, slotWrites(svc))
}
