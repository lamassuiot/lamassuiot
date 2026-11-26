package dmsmanager

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"testing"
	"uuid"

	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/assemblers/tests"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/require"
)

// bindFixture is a DMS with its enrollment CA, to bind certificates of that CA to devices of that DMS.
type bindFixture struct {
	dmsMgr      *tests.DMSManagerTestServer
	testServers *tests.TestServer
	enrollCA    *models.CACertificate
	dms         *models.DMS
}

func newBindFixture(t *testing.T) *bindFixture {
	t.Helper()
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

	return &bindFixture{dmsMgr: dmsMgr, testServers: testServers, enrollCA: enrollCA, dms: dms}
}

// createDevice registers a device of the fixture's DMS, decommissioned when asked to, and returns its ID.
func (f *bindFixture) createDevice(t *testing.T, prefix string, decommissioned bool) string {
	t.Helper()
	ctx := context.Background()

	deviceID := fmt.Sprintf("%s-%s", prefix, uuid.NewV7().String())
	_, err := f.testServers.DeviceManager.Service.CreateDevice(ctx, services.CreateDeviceInput{
		ID:        deviceID,
		Alias:     deviceID,
		Tags:      []string{},
		Metadata:  map[string]any{},
		DMSID:     f.dms.ID,
		Icon:      "test",
		IconColor: "#000000",
	})
	require.NoError(t, err)

	if decommissioned {
		_, err = f.testServers.DeviceManager.Service.UpdateDeviceStatus(ctx, services.UpdateDeviceStatusInput{
			ID:        deviceID,
			NewStatus: models.DeviceDecommissioned,
		})
		require.NoError(t, err)
	}
	return deviceID
}

// sign issues a certificate of the enrollment CA with common name cn.
func (f *bindFixture) sign(t *testing.T, cn string) *models.Certificate {
	t.Helper()
	key, _ := chelpers.GenerateECDSAKey(elliptic.P224())
	csr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: cn}, key)
	crt, err := f.testServers.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
		CAID:              f.enrollCA.ID,
		CertRequest:       (*models.X509CertificateRequest)(csr),
		IssuanceProfileID: f.enrollCA.ProfileID,
	})
	require.NoError(t, err)
	return crt
}

// requireNotAttached fails if the certificate was marked as attached to a device.
func (f *bindFixture) requireNotAttached(t *testing.T, serialNumber string) {
	t.Helper()
	stored, err := f.testServers.CA.Service.GetCertificateBySerialNumber(context.Background(), services.GetCertificatesBySerialNumberInput{SerialNumber: serialNumber})
	require.NoError(t, err)
	require.NotContains(t, stored.Metadata, models.DMSAttachedToDeviceKey)
}

// Binding a certificate to a decommissioned device is rejected before anything changes: the certificate is not marked
// as attached to the device.
func TestBindIdentityToDecommissionedDeviceIsRejected(t *testing.T) {
	f := newBindFixture(t)
	deviceID := f.createDevice(t, "decommissioned-device", true)
	crt := f.sign(t, deviceID)

	_, err := f.dmsMgr.Service.BindIdentityToDevice(context.Background(), services.BindIdentityToDeviceInput{
		DeviceID:                deviceID,
		CertificateSerialNumber: crt.SerialNumber,
		BindMode:                models.DeviceEventTypeProvisioned,
	})
	require.ErrorIs(t, err, errs.ErrDeviceInvalidStatus)
	f.requireNotAttached(t, crt.SerialNumber)
}

// The identity slot written is the one of the device the certificate names. Binding it to another device is rejected
// before anything changes: here, the certificate of a decommissioned device would be attached to an active one.
func TestBindIdentityOfAnotherDeviceIsRejected(t *testing.T) {
	f := newBindFixture(t)
	activeID := f.createDevice(t, "active-device", false)
	decommissionedID := f.createDevice(t, "decommissioned-device", true)
	crt := f.sign(t, decommissionedID)

	_, err := f.dmsMgr.Service.BindIdentityToDevice(context.Background(), services.BindIdentityToDeviceInput{
		DeviceID:                activeID,
		CertificateSerialNumber: crt.SerialNumber,
		BindMode:                models.DeviceEventTypeProvisioned,
	})
	require.ErrorIs(t, err, errs.ErrValidateBadRequest)
	f.requireNotAttached(t, crt.SerialNumber)
}
