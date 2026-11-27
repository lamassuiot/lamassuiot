package dmsmanager

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"testing"
	"time"
	"uuid"

	"github.com/globalsign/est"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/helpers"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestESTEnrollRegisteredDeviceWithoutIdentity covers enrollment of a device
// that exists before it enrolls (pre-registered, or created by hand in a JITP
// DMS). Refusing replaceable enrollment must only stop a device that already
// holds an identity, and a decommissioned device must never get a certificate.
func TestESTEnrollRegisteredDeviceWithoutIdentity(t *testing.T) {
	ctx := context.Background()

	dmsMgr, testServers, err := StartDMSManagerServiceTestServer(t)
	require.NoError(t, err, "could not create DMS Manager test server")

	createCA := func(t *testing.T, name string) *models.CACertificate {
		dur, _ := models.ParseDuration("1y")
		profile, err := testServers.CA.Service.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
			Profile: models.IssuanceProfile{
				Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)},
			},
		})
		require.NoError(t, err, "could not create issuance profile")

		ca, err := testServers.CA.Service.CreateCA(ctx, services.CreateCAInput{
			KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256},
			Subject:      models.Subject{CommonName: name},
			CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(dur)},
			ProfileID:    profile.ID,
			Metadata:     map[string]any{},
		})
		require.NoError(t, err, "could not create CA %s", name)
		return ca
	}

	type fixture struct {
		dms      *models.DMS
		enrollCA *models.CACertificate
		estCli   est.Client
	}

	setup := func(t *testing.T, mode models.RegistrationMode, replaceable bool) fixture {
		bootstrapCA := createCA(t, "boot")
		enrollCA := createCA(t, "enroll")

		dms, err := dmsMgr.Service.CreateDMS(ctx, services.CreateDMSInput{
			ID:       uuid.NewV7().String(),
			Name:     "first-identity",
			Metadata: map[string]any{},
			Settings: models.DMSSettings{
				EnrollmentSettings: models.EnrollmentSettings{
					EnrollmentProtocol: models.EST,
					EnrollmentCA:       enrollCA.ID,
					EnrollmentOptionsESTRFC7030: models.EnrollmentOptionsESTRFC7030{
						AuthMode: models.ESTAuthModeClientCertificate,
						AuthOptionsMTLS: models.AuthOptionsClientCertificate{
							ChainLevelValidation: -1,
							ValidationCAs:        []string{bootstrapCA.ID},
						},
					},
					DeviceProvisionProfile: models.DeviceProvisionProfile{
						Metadata: map[string]any{},
						Tags:     []string{},
					},
					RegistrationMode:            mode,
					EnableReplaceableEnrollment: replaceable,
					VerifyCSRSignature:          true,
				},
				ReEnrollmentSettings: models.ReEnrollmentSettings{
					ReEnrollmentDelta:           models.TimeDuration(time.Hour),
					PreventiveReEnrollmentDelta: models.TimeDuration(time.Minute * 3),
					CriticalReEnrollmentDelta:   models.TimeDuration(time.Minute * 2),
				},
				CADistributionSettings: models.CADistributionSettings{ManagedCAs: []string{}},
			},
		})
		require.NoError(t, err, "could not create DMS")

		bootKey, _ := chelpers.GenerateECDSAKey(elliptic.P256())
		bootCSR, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
		bootCrt, err := testServers.CA.Service.SignCertificate(ctx, services.SignCertificateInput{
			CAID:              bootstrapCA.ID,
			CertRequest:       (*models.X509CertificateRequest)(bootCSR),
			IssuanceProfileID: bootstrapCA.ProfileID,
		})
		require.NoError(t, err, "could not sign bootstrap certificate")

		return fixture{
			dms:      dms,
			enrollCA: enrollCA,
			estCli: est.Client{
				Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
				AdditionalPathSegment: dms.ID,
				Certificates:          []*x509.Certificate{(*x509.Certificate)(bootCrt.Certificate)},
				PrivateKey:            bootKey,
				InsecureSkipVerify:    true,
			},
		}
	}

	registerDevice := func(t *testing.T, dmsID string) string {
		deviceID := fmt.Sprintf("registered-device-%s", uuid.NewV7().String())
		_, err := testServers.DeviceManager.Service.CreateDevice(ctx, services.CreateDeviceInput{
			ID:        deviceID,
			Alias:     deviceID,
			Tags:      []string{},
			Metadata:  map[string]any{},
			DMSID:     dmsID,
			Icon:      "test",
			IconColor: "#000000",
		})
		require.NoError(t, err, "could not register device")
		return deviceID
	}

	newCSR := func(deviceID string) *x509.CertificateRequest {
		key, _ := chelpers.GenerateECDSAKey(elliptic.P256())
		csr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, key)
		return csr
	}

	assertFirstEnrollment := func(t *testing.T, f fixture, deviceID string) {
		crt, err := f.estCli.Enroll(ctx, newCSR(deviceID))
		require.NoError(t, err, "first enrollment of a device without identity must succeed")
		assert.Equal(t, deviceID, crt.Subject.CommonName)
		assert.NoError(t, crt.CheckSignatureFrom((*x509.Certificate)(f.enrollCA.Certificate.Certificate)))

		device, err := testServers.DeviceManager.Service.GetDeviceByID(ctx, services.GetDeviceByIDInput{ID: deviceID})
		require.NoError(t, err)
		require.NotNil(t, device.IdentitySlot, "the issued certificate must be bound to the device")
		assert.Equal(t, helpers.SerialNumberToHexString(crt.SerialNumber), device.IdentitySlot.Secrets[device.IdentitySlot.ActiveVersion])
	}

	for _, mode := range []models.RegistrationMode{models.PreRegistration, models.JITP} {
		t.Run(fmt.Sprintf("%s/NotReplaceable/FirstEnrollmentSucceeds", mode), func(t *testing.T) {
			f := setup(t, mode, false)
			deviceID := registerDevice(t, f.dms.ID)
			assertFirstEnrollment(t, f, deviceID)
		})

		t.Run(fmt.Sprintf("%s/NotReplaceable/SecondEnrollmentIsForbidden", mode), func(t *testing.T) {
			f := setup(t, mode, false)
			deviceID := registerDevice(t, f.dms.ID)
			assertFirstEnrollment(t, f, deviceID)

			_, err := f.estCli.Enroll(ctx, newCSR(deviceID))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "forbiddenNewEnrollment")
		})
	}

	t.Run("PRE_REGISTRATION/Replaceable/FirstEnrollmentSucceeds", func(t *testing.T) {
		f := setup(t, models.PreRegistration, true)
		deviceID := registerDevice(t, f.dms.ID)
		assertFirstEnrollment(t, f, deviceID)
	})

	for _, replaceable := range []bool{false, true} {
		t.Run(fmt.Sprintf("PRE_REGISTRATION/Replaceable=%t/DecommissionedDeviceIsRejected", replaceable), func(t *testing.T) {
			f := setup(t, models.PreRegistration, replaceable)
			deviceID := registerDevice(t, f.dms.ID)
			_, err := testServers.DeviceManager.Service.UpdateDeviceStatus(ctx, services.UpdateDeviceStatusInput{
				ID:        deviceID,
				NewStatus: models.DeviceDecommissioned,
			})
			require.NoError(t, err, "could not decommission device")

			_, err = f.estCli.Enroll(ctx, newCSR(deviceID))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "device decommissioned")

			certs := []*models.Certificate{}
			_, err = testServers.CA.Service.GetCertificatesByCA(ctx, services.GetCertificatesByCAInput{
				CAID: f.enrollCA.ID,
				ListInput: resources.ListInput[models.Certificate]{
					ExhaustiveRun: true,
					ApplyFunc: func(c models.Certificate) {
						if c.Subject.CommonName == deviceID {
							certs = append(certs, &c)
						}
					},
				},
			})
			require.NoError(t, err)
			assert.Empty(t, certs, "no certificate may be issued for a decommissioned device")
		})
	}

	// A device can be decommissioned after the enrollment checked it and before the CA signed. Binding must then
	// fail instead of reporting success for a certificate the device does not hold.
	t.Run("BindIdentityToDeviceRejectsDecommissionedDevice", func(t *testing.T) {
		f := setup(t, models.PreRegistration, false)
		deviceID := registerDevice(t, f.dms.ID)
		crt, err := testServers.CA.Service.SignCertificate(ctx, services.SignCertificateInput{
			CAID:              f.enrollCA.ID,
			CertRequest:       (*models.X509CertificateRequest)(newCSR(deviceID)),
			IssuanceProfileID: f.enrollCA.ProfileID,
		})
		require.NoError(t, err)
		_, err = testServers.DeviceManager.Service.UpdateDeviceStatus(ctx, services.UpdateDeviceStatusInput{
			ID:        deviceID,
			NewStatus: models.DeviceDecommissioned,
		})
		require.NoError(t, err, "could not decommission device")

		_, err = dmsMgr.Service.BindIdentityToDevice(ctx, services.BindIdentityToDeviceInput{
			DeviceID:                deviceID,
			CertificateSerialNumber: crt.SerialNumber,
			BindMode:                models.DeviceEventTypeProvisioned,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "device decommissioned")

		device, err := testServers.DeviceManager.Service.GetDeviceByID(ctx, services.GetDeviceByIDInput{ID: deviceID})
		require.NoError(t, err)
		assert.Nil(t, device.IdentitySlot)
	})
}
