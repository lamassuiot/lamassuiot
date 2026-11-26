package dmsmanager

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"testing"
	"uuid"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/require"
)

// Binding a certificate to a decommissioned device is rejected before anything changes: the certificate is not marked
// as attached to the device.
func TestBindIdentityToDecommissionedDeviceIsRejected(t *testing.T) {
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

	deviceID := fmt.Sprintf("decommissioned-device-%s", uuid.NewV7().String())
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

	_, err = testServers.DeviceManager.Service.UpdateDeviceStatus(ctx, services.UpdateDeviceStatusInput{
		ID:        deviceID,
		NewStatus: models.DeviceDecommissioned,
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
	require.ErrorIs(t, err, errs.ErrDeviceInvalidStatus)

	stored, err := testServers.CA.Service.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{SerialNumber: crt.SerialNumber})
	require.NoError(t, err)
	require.NotContains(t, stored.Metadata, models.DMSAttachedToDeviceKey)
}
