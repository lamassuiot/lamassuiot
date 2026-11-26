package services

import (
	"context"
	"io"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	coreservices "github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

type slotDevicesRepo struct {
	storage.DeviceManagerRepo
	device models.Device
}

func (repo *slotDevicesRepo) SelectExists(context.Context, string) (bool, *models.Device, error) {
	device := repo.device
	return true, &device, nil
}

func (repo *slotDevicesRepo) Update(_ context.Context, device *models.Device) (*models.Device, error) {
	repo.device = *device
	return device, nil
}

func (repo *slotDevicesRepo) DeviceEvents() storage.DeviceEventsRepo { return slotEventsRepo{} }

type slotEventsRepo struct{ storage.DeviceEventsRepo }

func (slotEventsRepo) Insert(_ context.Context, event *models.DeviceEventRecord) (*models.DeviceEventRecord, error) {
	return event, nil
}

// slotCA holds the identity certificate of the device and records its status updates, with the status the stored
// device had when each update arrived.
type slotCA struct {
	coreservices.CAService
	cert             models.Certificate
	updates          []coreservices.UpdateCertificateStatusInput
	repo             *slotDevicesRepo
	statusesAtUpdate []models.DeviceStatus
}

func (ca *slotCA) GetCertificateBySerialNumber(context.Context, coreservices.GetCertificatesBySerialNumberInput) (*models.Certificate, error) {
	cert := ca.cert
	return &cert, nil
}

func (ca *slotCA) UpdateCertificateStatus(_ context.Context, input coreservices.UpdateCertificateStatusInput) (*models.Certificate, error) {
	ca.updates = append(ca.updates, input)
	if ca.repo != nil {
		ca.statusesAtUpdate = append(ca.statusesAtUpdate, ca.repo.device.Status)
	}
	ca.cert.Status = input.NewStatus
	ca.cert.RevocationReason = input.RevocationReason
	delete(ca.cert.Metadata, models.CAMetadataSuspendedByCascadeKey)
	return &ca.cert, nil
}

// newSlotFixture holds the device "dev-1", whose identity certificate "sn-1" a CA hold put on hold. slotStatus is the
// status of its identity slot.
func newSlotFixture(t *testing.T, slotStatus models.SlotStatus) (*DeviceManagerServiceBackend, *slotCA) {
	t.Helper()
	previous := deviceValidate
	deviceValidate = validator.New()
	t.Cleanup(func() { deviceValidate = previous })

	ca := &slotCA{cert: models.Certificate{
		SerialNumber: "sn-1", Status: models.StatusRevoked, RevocationReason: ocsp.CertificateHold,
		Metadata: map[string]any{models.CAMetadataSuspendedByCascadeKey: "ca-1"},
	}}
	repo := &slotDevicesRepo{device: models.Device{
		ID: "dev-1", Status: models.DeviceActive,
		IdentitySlot: &models.Slot[string]{Status: slotStatus, ActiveVersion: 0, Secrets: map[int]string{0: "sn-1"}},
	}}
	ca.repo = repo
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	svc := &DeviceManagerServiceBackend{devicesStorage: repo, caClient: ca, logger: logrus.NewEntry(logger)}
	svc.service = svc
	return svc, ca
}

func revokedSlot() models.Slot[string] {
	return models.Slot[string]{Status: models.SlotRevoke, ActiveVersion: 0, Secrets: map[int]string{0: "sn-1"}}
}

// An operator that revokes a device whose certificate is on hold revokes it for good: the hold of its CA must not
// release it. Revoking the certificate removes the mark that the release looks for.
func TestRevokingTheSlotOfAHeldCertificateRevokesItForGood(t *testing.T) {
	svc, ca := newSlotFixture(t, models.SlotRevoke)

	_, err := svc.UpdateDeviceIdentitySlot(context.Background(), coreservices.UpdateDeviceIdentitySlotInput{ID: "dev-1", Slot: revokedSlot()})
	require.NoError(t, err)

	require.Len(t, ca.updates, 1)
	require.Equal(t, models.StatusRevoked, ca.cert.Status)
	require.Equal(t, models.RevocationReason(ocsp.Unspecified), ca.cert.RevocationReason)
	require.NotContains(t, ca.cert.Metadata, models.CAMetadataSuspendedByCascadeKey)
}

// The operator may revoke before the event of the hold reaches the device manager: the slot still reads active.
func TestRevokingTheSlotBeforeTheHoldEventRevokesItForGood(t *testing.T) {
	svc, ca := newSlotFixture(t, models.SlotActive)

	_, err := svc.UpdateDeviceIdentitySlot(context.Background(), coreservices.UpdateDeviceIdentitySlotInput{ID: "dev-1", Slot: revokedSlot()})
	require.NoError(t, err)

	require.Equal(t, models.RevocationReason(ocsp.Unspecified), ca.cert.RevocationReason)
	require.NotContains(t, ca.cert.Metadata, models.CAMetadataSuspendedByCascadeKey)
}

// A sync with the certificate (the event of the hold itself): the hold and its mark stay as the cascade left them.
func TestSyncingTheSlotWithAHeldCertificateKeepsTheHold(t *testing.T) {
	svc, ca := newSlotFixture(t, models.SlotActive)

	_, err := svc.UpdateDeviceIdentitySlot(context.Background(), coreservices.UpdateDeviceIdentitySlotInput{
		ID: "dev-1", Slot: revokedSlot(), SyncCertificateStatus: true,
	})
	require.NoError(t, err)

	require.Empty(t, ca.updates)
	require.Equal(t, models.RevocationReason(ocsp.CertificateHold), ca.cert.RevocationReason)
	require.Equal(t, "ca-1", ca.cert.Metadata[models.CAMetadataSuspendedByCascadeKey])
}

// A decommissioned device is retired for good: writing its identity slot must fail instead of reporting a success
// that stored nothing, so that no caller binds a new certificate to it.
func TestUpdatingTheSlotOfADecommissionedDeviceIsRejected(t *testing.T) {
	svc, ca := newSlotFixture(t, models.SlotRevoke)
	repo := svc.devicesStorage.(*slotDevicesRepo)
	repo.device.Status = models.DeviceDecommissioned

	dev, err := svc.UpdateDeviceIdentitySlot(context.Background(), coreservices.UpdateDeviceIdentitySlotInput{ID: "dev-1", Slot: revokedSlot()})
	require.ErrorIs(t, err, errs.ErrDeviceInvalidStatus)
	require.Nil(t, dev)

	require.Empty(t, ca.updates)
	require.Equal(t, models.DeviceDecommissioned, repo.device.Status)
}

func decommission(t *testing.T, svc *DeviceManagerServiceBackend) {
	t.Helper()
	_, err := svc.UpdateDeviceStatus(context.Background(), coreservices.UpdateDeviceStatusInput{ID: "dev-1", NewStatus: models.DeviceDecommissioned})
	require.NoError(t, err)
	require.Equal(t, models.DeviceDecommissioned, svc.devicesStorage.(*slotDevicesRepo).device.Status)
}

// A revoked slot can hide a certificate on hold. Decommissioning must revoke it for good: otherwise releasing the CA
// that put it on hold reactivates the certificate of a device that is retired.
func TestDecommissioningADeviceWhoseCertificateIsOnHoldRevokesItForGood(t *testing.T) {
	svc, ca := newSlotFixture(t, models.SlotRevoke)

	decommission(t, svc)

	require.Len(t, ca.updates, 1)
	require.Equal(t, "sn-1", ca.updates[0].SerialNumber)
	require.Equal(t, models.StatusRevoked, ca.cert.Status)
	require.Equal(t, models.RevocationReason(ocsp.CessationOfOperation), ca.cert.RevocationReason)
	require.NotContains(t, ca.cert.Metadata, models.CAMetadataSuspendedByCascadeKey)
	// The device is stored as decommissioned before the revocation, whose event the device handler must skip.
	require.Equal(t, []models.DeviceStatus{models.DeviceDecommissioned}, ca.statusesAtUpdate)
}

// The slot may still read revoked while its certificate is already active again (the release of a hold whose event
// has not reached the device yet). Decommissioning revokes that certificate too.
func TestDecommissioningADeviceWithARevokedSlotButAnActiveCertificateRevokesIt(t *testing.T) {
	svc, ca := newSlotFixture(t, models.SlotRevoke)
	ca.cert = models.Certificate{SerialNumber: "sn-1", Status: models.StatusActive, Metadata: map[string]any{}}

	decommission(t, svc)

	require.Len(t, ca.updates, 1)
	require.Equal(t, "sn-1", ca.updates[0].SerialNumber)
	require.Equal(t, models.StatusRevoked, ca.cert.Status)
	require.Equal(t, models.RevocationReason(ocsp.CessationOfOperation), ca.cert.RevocationReason)
	require.Equal(t, []models.DeviceStatus{models.DeviceDecommissioned}, ca.statusesAtUpdate)
}

// A certificate already revoked for good stays as it is: the CA could not change it anyway.
func TestDecommissioningADeviceWhoseCertificateIsRevokedForGoodLeavesIt(t *testing.T) {
	svc, ca := newSlotFixture(t, models.SlotRevoke)
	ca.cert = models.Certificate{SerialNumber: "sn-1", Status: models.StatusRevoked, RevocationReason: ocsp.KeyCompromise, Metadata: map[string]any{}}

	decommission(t, svc)

	require.Empty(t, ca.updates)
	require.Equal(t, models.RevocationReason(ocsp.KeyCompromise), ca.cert.RevocationReason)
}
