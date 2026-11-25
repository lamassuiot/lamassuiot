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
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/assemblers/tests"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/helpers"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type enrollBindFixture struct {
	dmsMgr      *tests.DMSManagerTestServer
	testServers *tests.TestServer
	// profile is the default issuance profile of the enrollment CA, which the DMS uses.
	profile  *models.IssuanceProfile
	enrollCA *models.CACertificate
	dms      *models.DMS
	estCli   est.Client
}

// newEnrollBindFixture builds a DMS with JIT registration and replaceable enrollment, plus an EST client
// authenticated with a bootstrap certificate.
func newEnrollBindFixture(t *testing.T) enrollBindFixture {
	t.Helper()
	ctx := context.Background()

	dmsMgr, testServers, err := StartDMSManagerServiceTestServer(t)
	require.NoError(t, err, "could not create DMS Manager test server")

	lifespanCADur, _ := models.ParseDuration("1y")
	issuanceDur, _ := models.ParseDuration("30d")
	profile, err := testServers.CA.Service.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Validity: models.Validity{Type: models.Duration, Duration: (models.TimeDuration)(issuanceDur)},
		},
	})
	require.NoError(t, err, "could not create issuance profile")

	createCA := func(cn string) *models.CACertificate {
		ca, err := testServers.CA.Service.CreateCA(ctx, services.CreateCAInput{
			KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 224},
			Subject:      models.Subject{CommonName: cn},
			CAExpiration: models.Validity{Type: models.Duration, Duration: (models.TimeDuration)(lifespanCADur)},
			ProfileID:    profile.ID,
			Metadata:     map[string]any{},
		})
		require.NoError(t, err, "could not create CA %s", cn)
		return ca
	}
	bootstrapCA := createCA("bootstrap-ca")
	enrollCA := createCA("enrollment-ca")

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
						ValidationCAs:        []string{bootstrapCA.ID},
					},
				},
				DeviceProvisionProfile: models.DeviceProvisionProfile{
					Icon:      "BiSolidCreditCardFront",
					IconColor: "#25ee32",
					Metadata:  map[string]any{},
					Tags:      []string{"test"},
				},
				RegistrationMode:            models.JITP,
				EnableReplaceableEnrollment: true,
				VerifyCSRSignature:          true,
			},
			ReEnrollmentSettings: models.ReEnrollmentSettings{
				ReEnrollmentOptionsESTRFC7030: models.EnrollmentOptionsESTRFC7030{
					AuthMode: models.ESTAuthModeClientCertificate,
				},
				ReEnrollmentDelta:           models.TimeDuration(24 * 365 * time.Hour),
				PreventiveReEnrollmentDelta: models.TimeDuration(time.Minute * 3),
				CriticalReEnrollmentDelta:   models.TimeDuration(time.Minute * 2),
			},
			CADistributionSettings: models.CADistributionSettings{
				IncludeLamassuSystemCA: true,
				IncludeEnrollmentCA:    true,
				ManagedCAs:             []string{},
			},
		},
	})
	require.NoError(t, err, "could not create DMS")

	bootKey, _ := chelpers.GenerateECDSAKey(elliptic.P224())
	bootCsr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
	bootCrt, err := testServers.CA.Service.SignCertificate(ctx, services.SignCertificateInput{
		CAID:              bootstrapCA.ID,
		CertRequest:       (*models.X509CertificateRequest)(bootCsr),
		IssuanceProfileID: bootstrapCA.ProfileID,
	})
	require.NoError(t, err, "could not sign bootstrap certificate")

	return enrollBindFixture{
		dmsMgr:      dmsMgr,
		testServers: testServers,
		profile:     profile,
		enrollCA:    enrollCA,
		dms:         dms,
		estCli: est.Client{
			Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
			AdditionalPathSegment: dms.ID,
			Certificates:          []*x509.Certificate{(*x509.Certificate)(bootCrt.Certificate)},
			PrivateKey:            bootKey,
			InsecureSkipVerify:    true,
		},
	}
}

// The device to bind is the one named in the input. The certificate CommonName may differ from the device ID,
// for instance when an issuance profile overrides the subject.
func TestBindIdentityToDeviceTargetsInputDeviceNotCertificateCN(t *testing.T) {
	ctx := context.Background()
	fx := newEnrollBindFixture(t)

	deviceID := fmt.Sprintf("device-%s", uuid.NewV7().String())
	_, err := fx.testServers.DeviceManager.Service.CreateDevice(ctx, services.CreateDeviceInput{
		ID:        deviceID,
		Alias:     deviceID,
		Tags:      []string{},
		Metadata:  map[string]any{},
		DMSID:     fx.dms.ID,
		Icon:      "BiSolidCreditCardFront",
		IconColor: "#25ee32",
	})
	require.NoError(t, err, "could not create device")

	key, _ := chelpers.GenerateECDSAKey(elliptic.P224())
	csr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: fmt.Sprintf("other-cn-%s", uuid.NewV7().String())}, key)
	crt, err := fx.testServers.CA.Service.SignCertificate(ctx, services.SignCertificateInput{
		CAID:              fx.enrollCA.ID,
		CertRequest:       (*models.X509CertificateRequest)(csr),
		IssuanceProfileID: fx.enrollCA.ProfileID,
	})
	require.NoError(t, err, "could not sign certificate")

	_, err = fx.dmsMgr.Service.BindIdentityToDevice(ctx, services.BindIdentityToDeviceInput{
		DeviceID:                deviceID,
		CertificateSerialNumber: crt.SerialNumber,
		BindMode:                models.DeviceEventTypeProvisioned,
	})
	require.NoError(t, err, "binding should target the input device")

	device, err := fx.testServers.DeviceManager.Service.GetDeviceByID(ctx, services.GetDeviceByIDInput{ID: deviceID})
	require.NoError(t, err)
	require.NotNil(t, device.IdentitySlot, "identity slot should be set")
	assert.Equal(t, crt.SerialNumber, device.IdentitySlot.Secrets[device.IdentitySlot.ActiveVersion])
}

// A replaceable enrollment that fails must not revoke the certificate the device is currently using: there is no
// new certificate to replace it.
func TestEnrollFailedReplacementKeepsCurrentCertificateActive(t *testing.T) {
	ctx := context.Background()
	fx := newEnrollBindFixture(t)

	deviceID := fmt.Sprintf("device-%s", uuid.NewV7().String())
	key, _ := chelpers.GenerateECDSAKey(elliptic.P224())
	csr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, key)

	firstCrt, err := fx.estCli.Enroll(ctx, csr)
	require.NoError(t, err, "first enrollment should succeed")
	firstSN := helpers.SerialNumberToHexString(firstCrt.SerialNumber)

	// Make the next enrollment fail at signing, after the device check: the profile no longer accepts ECDSA keys.
	profile := *fx.profile
	profile.CryptoEnforcement = models.IssuanceProfileCryptoEnforcement{Enabled: true, AllowRSAKeys: true}
	_, err = fx.testServers.CA.Service.UpdateIssuanceProfile(ctx, services.UpdateIssuanceProfileInput{Profile: profile})
	require.NoError(t, err, "could not update issuance profile")

	_, err = fx.estCli.Enroll(ctx, csr)
	require.Error(t, err, "second enrollment should fail")

	current, err := fx.testServers.CA.Service.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{
		SerialNumber: firstSN,
	})
	require.NoError(t, err)
	assert.Equal(t, models.StatusActive, current.Status, "current certificate must stay active when the replacement fails")

	device, err := fx.testServers.DeviceManager.Service.GetDeviceByID(ctx, services.GetDeviceByIDInput{ID: deviceID})
	require.NoError(t, err)
	require.NotNil(t, device.IdentitySlot)
	assert.Equal(t, firstSN, device.IdentitySlot.Secrets[device.IdentitySlot.ActiveVersion])
}
