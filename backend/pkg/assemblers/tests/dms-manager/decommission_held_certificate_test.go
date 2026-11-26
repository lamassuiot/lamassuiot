package dmsmanager

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"testing"
	"uuid"

	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

// A device decommissioned while the hold of its CA keeps its certificate on hold must not get that certificate back
// when the CA is released: decommissioning revokes it for good.
func TestReleasingTheCADoesNotReactivateTheCertificateOfADecommissionedDevice(t *testing.T) {
	ctx := context.Background()

	dmsMgr, testServers, err := StartDMSManagerServiceTestServer(t)
	require.NoError(t, err, "could not create DMS Manager test server")

	lifespan, _ := models.ParseDuration("1y")
	issuance, _ := models.ParseDuration("30d")
	profile, err := testServers.CA.Service.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{Validity: models.Validity{Type: models.Duration, Duration: (models.TimeDuration)(issuance)}},
	})
	require.NoError(t, err)

	enrollCA, err := testServers.CA.Service.CreateCA(ctx, services.CreateCAInput{
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 224},
		Subject:      models.Subject{CommonName: "enrollment-ca"},
		CAExpiration: models.Validity{Type: models.Duration, Duration: (models.TimeDuration)(lifespan)},
		ProfileID:    profile.ID,
		Metadata:     map[string]any{},
	})
	require.NoError(t, err)

	dms, err := dmsMgr.Service.CreateDMS(ctx, services.CreateDMSInput{
		ID:       uuid.NewV7().String(),
		Name:     "TestDMS",
		Metadata: map[string]any{},
		Settings: models.DMSSettings{
			EnrollmentSettings: models.EnrollmentSettings{
				EnrollmentProtocol: models.EST,
				EnrollmentCA:       enrollCA.ID,
				EnrollmentOptionsESTRFC7030: models.EnrollmentOptionsESTRFC7030{
					AuthMode: models.ESTAuthModeClientCertificate,
					AuthOptionsMTLS: models.AuthOptionsClientCertificate{
						ChainLevelValidation: -1,
						ValidationCAs:        []string{},
					},
				},
				DeviceProvisionProfile: models.DeviceProvisionProfile{Metadata: map[string]any{}, Tags: []string{}},
				RegistrationMode:       models.JITP,
			},
		},
	})
	require.NoError(t, err)

	// A provisioned device: its identity slot holds a certificate of the enrollment CA.
	deviceID := fmt.Sprintf("held-device-%s", uuid.NewV7().String())
	_, err = testServers.DeviceManager.Service.CreateDevice(ctx, services.CreateDeviceInput{
		ID:        deviceID,
		Alias:     deviceID,
		Tags:      []string{},
		Metadata:  map[string]any{},
		DMSID:     dms.ID,
		Icon:      "test",
		IconColor: "#000000",
	})
	require.NoError(t, err)

	key, _ := chelpers.GenerateECDSAKey(elliptic.P224())
	csr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, key)
	crt, err := testServers.CA.Service.SignCertificate(ctx, services.SignCertificateInput{
		CAID:              enrollCA.ID,
		CertRequest:       (*models.X509CertificateRequest)(csr),
		IssuanceProfileID: enrollCA.ProfileID,
	})
	require.NoError(t, err)

	_, err = dmsMgr.Service.BindIdentityToDevice(ctx, services.BindIdentityToDeviceInput{
		DeviceID:                deviceID,
		CertificateSerialNumber: crt.SerialNumber,
		BindMode:                models.DeviceEventTypeProvisioned,
	})
	require.NoError(t, err)

	// The CA goes on hold: its cascade holds the device certificate, and the slot follows it.
	_, err = testServers.CA.Service.UpdateCAStatus(ctx, services.UpdateCAStatusInput{
		CAID:             enrollCA.ID,
		Status:           models.StatusRevoked,
		RevocationReason: ocsp.CertificateHold,
	})
	require.NoError(t, err)

	device, err := testServers.DeviceManager.Service.GetDeviceByID(ctx, services.GetDeviceByIDInput{ID: deviceID})
	require.NoError(t, err)
	slot := *device.IdentitySlot
	slot.Status = models.SlotRevoke
	_, err = testServers.DeviceManager.Service.UpdateDeviceIdentitySlot(ctx, services.UpdateDeviceIdentitySlotInput{
		ID:                    deviceID,
		Slot:                  slot,
		SyncCertificateStatus: true,
	})
	require.NoError(t, err)

	held, err := testServers.CA.Service.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{SerialNumber: crt.SerialNumber})
	require.NoError(t, err)
	require.Equal(t, models.StatusRevoked, held.Status)
	require.Equal(t, models.RevocationReason(ocsp.CertificateHold), held.RevocationReason)

	_, err = testServers.DeviceManager.Service.UpdateDeviceStatus(ctx, services.UpdateDeviceStatusInput{
		ID:        deviceID,
		NewStatus: models.DeviceDecommissioned,
	})
	require.NoError(t, err)

	// Releasing the CA releases what its hold put on hold, but not the certificate of the decommissioned device.
	_, err = testServers.CA.Service.UpdateCAStatus(ctx, services.UpdateCAStatusInput{
		CAID:   enrollCA.ID,
		Status: models.StatusActive,
	})
	require.NoError(t, err)

	after, err := testServers.CA.Service.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{SerialNumber: crt.SerialNumber})
	require.NoError(t, err)
	require.Equal(t, models.StatusRevoked, after.Status)
	require.Equal(t, models.RevocationReason(ocsp.CessationOfOperation), after.RevocationReason)
}
