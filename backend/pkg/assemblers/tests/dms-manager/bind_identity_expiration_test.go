package dmsmanager

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"github.com/globalsign/est"
	"github.com/google/uuid"
	identityextractors "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/identity-extractors"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBindIdentityToDevice_SetsExpirationDate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	dmsMgr, testServers, err := StartDMSManagerServiceTestServer(t, false)
	require.NoError(t, err, "could not create DMS Manager test server")

	// Create CA with specific validity period
	lifespanCADur, _ := models.ParseDuration("1y")
	issuanceCADur, _ := models.ParseDuration("30d") // Certificate valid for 30 days

	profile, err := testServers.CA.Service.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Validity: models.Validity{Type: models.Duration, Duration: (models.TimeDuration)(issuanceCADur)},
		},
	})
	require.NoError(t, err, "could not create issuance profile")

	bootstrapCA, err := testServers.CA.Service.CreateCA(ctx, services.CreateCAInput{
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 224},
		Subject:      models.Subject{CommonName: "bootstrap-ca"},
		CAExpiration: models.Validity{Type: models.Duration, Duration: (models.TimeDuration)(lifespanCADur)},
		ProfileID:    profile.ID,
		Metadata:     map[string]any{},
	})
	require.NoError(t, err, "could not create bootstrap CA")

	enrollCA, err := testServers.CA.Service.CreateCA(ctx, services.CreateCAInput{
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 224},
		Subject:      models.Subject{CommonName: "enrollment-ca"},
		CAExpiration: models.Validity{Type: models.Duration, Duration: (models.TimeDuration)(lifespanCADur)},
		ProfileID:    profile.ID,
		Metadata:     map[string]any{},
	})
	require.NoError(t, err, "could not create enrollment CA")

	// Create DMS
	dms, err := dmsMgr.Service.CreateDMS(ctx, services.CreateDMSInput{
		ID:       uuid.NewString(),
		Name:     "TestDMS",
		Metadata: map[string]any{},
		Settings: models.DMSSettings{
			EnrollmentSettings: models.EnrollmentSettings{
				EnrollmentProtocol: models.EST,
				EnrollmentCA:       enrollCA.ID,
				EnrollmentOptionsESTRFC7030: models.EnrollmentOptionsESTRFC7030{
					AuthMode: models.ESTAuthMode(identityextractors.IdentityExtractorClientCertificate),
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
				AdditionalValidationCAs:     []string{},
				ReEnrollmentDelta:           models.TimeDuration(24 * 365 * time.Hour), // Allow re-enrollment any time within a year
				EnableExpiredRenewal:        true,
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

	// Create bootstrap certificate
	bootKey, _ := chelpers.GenerateECDSAKey(elliptic.P224())
	bootCsr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
	bootCrt, err := testServers.CA.Service.SignCertificate(ctx, services.SignCertificateInput{
		CAID:              bootstrapCA.ID,
		CertRequest:       (*models.X509CertificateRequest)(bootCsr),
		IssuanceProfileID: bootstrapCA.ProfileID,
	})
	require.NoError(t, err, "could not sign Bootstrap Certificate")

	// Setup EST client
	estCli := est.Client{
		Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
		AdditionalPathSegment: dms.ID,
		Certificates:          []*x509.Certificate{(*x509.Certificate)(bootCrt.Certificate)},
		PrivateKey:            bootKey,
		InsecureSkipVerify:    true,
	}

	t.Run("FirstEnrollment_SetsExpirationDate", func(t *testing.T) {
		deviceID := fmt.Sprintf("device-%s", uuid.NewString())
		enrollKey, _ := chelpers.GenerateECDSAKey(elliptic.P224())
		enrollCSR, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

		// Perform enrollment
		enrollCRT, err := estCli.Enroll(ctx, enrollCSR)
		require.NoError(t, err, "enrollment should succeed")

		// Get device from device manager
		device, err := testServers.DeviceManager.Service.GetDeviceByID(ctx, services.GetDeviceByIDInput{
			ID: deviceID,
		})
		require.NoError(t, err, "should get device by ID")

		// Verify identity slot exists
		require.NotNil(t, device.IdentitySlot, "identity slot should not be nil")

		// Verify expiration date is set
		require.NotNil(t, device.IdentitySlot.ExpirationDate, "expiration date should not be nil")

		// Verify expiration date matches certificate expiration (compare Unix timestamps to avoid timezone issues)
		assert.Equal(t, enrollCRT.NotAfter.Unix(), device.IdentitySlot.ExpirationDate.Unix(),
			"expiration date should match certificate NotAfter")

		// Verify the expiration is approximately 30 days from now (with 1 minute tolerance)
		expectedExpiration := time.Now().Add(30 * 24 * time.Hour)
		timeDiff := device.IdentitySlot.ExpirationDate.Sub(expectedExpiration)
		assert.Less(t, timeDiff.Abs(), time.Minute,
			"expiration should be approximately 30 days from now")
	})

	t.Run("ReEnrollment_UpdatesExpirationDate", func(t *testing.T) {
		deviceID := fmt.Sprintf("device-%s", uuid.NewString())
		enrollKey, _ := chelpers.GenerateECDSAKey(elliptic.P224())
		enrollCSR, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

		// First enrollment
		firstEnrollCRT, err := estCli.Enroll(ctx, enrollCSR)
		require.NoError(t, err, "first enrollment should succeed")

		// Get device after first enrollment
		device, err := testServers.DeviceManager.Service.GetDeviceByID(ctx, services.GetDeviceByIDInput{
			ID: deviceID,
		})
		require.NoError(t, err, "should get device by ID")
		require.NotNil(t, device.IdentitySlot.ExpirationDate, "expiration date should be set after first enrollment")
		firstExpirationDate := *device.IdentitySlot.ExpirationDate

		// Wait a moment to ensure different timestamps
		time.Sleep(2 * time.Second)

		// Update EST client with the newly issued certificate for re-enrollment
		estCliReenroll := est.Client{
			Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
			AdditionalPathSegment: dms.ID,
			Certificates:          []*x509.Certificate{firstEnrollCRT},
			PrivateKey:            enrollKey,
			InsecureSkipVerify:    true,
		}

		// Create new key and CSR for re-enrollment
		reenrollKey, _ := chelpers.GenerateECDSAKey(elliptic.P224())
		reenrollCSR, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, reenrollKey)

		// Perform re-enrollment
		secondEnrollCRT, err := estCliReenroll.Reenroll(ctx, reenrollCSR)
		require.NoError(t, err, "re-enrollment should succeed")

		// Get device after re-enrollment
		deviceAfterReenroll, err := testServers.DeviceManager.Service.GetDeviceByID(ctx, services.GetDeviceByIDInput{
			ID: deviceID,
		})
		require.NoError(t, err, "should get device by ID after re-enrollment")

		// Verify expiration date is updated
		require.NotNil(t, deviceAfterReenroll.IdentitySlot.ExpirationDate,
			"expiration date should still be set after re-enrollment")

		// Verify new expiration date matches new certificate (compare Unix timestamps to avoid timezone issues)
		assert.Equal(t, secondEnrollCRT.NotAfter.Unix(), deviceAfterReenroll.IdentitySlot.ExpirationDate.Unix(),
			"expiration date should match new certificate NotAfter")

		// Verify expiration date changed
		assert.NotEqual(t, firstExpirationDate, *deviceAfterReenroll.IdentitySlot.ExpirationDate,
			"expiration date should be updated after re-enrollment")

		// Verify new expiration is later than first expiration
		assert.True(t, deviceAfterReenroll.IdentitySlot.ExpirationDate.After(firstExpirationDate),
			"new expiration should be later than first expiration")
	})
}

func TestBindIdentityToDevice_DirectBinding_SetsExpirationDate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	dmsMgr, testServers, err := StartDMSManagerServiceTestServer(t, false)
	require.NoError(t, err, "could not create DMS Manager test server")

	// Create CA
	lifespanCADur, _ := models.ParseDuration("1y")
	issuanceCADur, _ := models.ParseDuration("60d")

	profile, err := testServers.CA.Service.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Validity: models.Validity{Type: models.Duration, Duration: (models.TimeDuration)(issuanceCADur)},
		},
	})
	require.NoError(t, err, "could not create issuance profile")

	testCA, err := testServers.CA.Service.CreateCA(ctx, services.CreateCAInput{
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 224},
		Subject:      models.Subject{CommonName: "test-ca"},
		CAExpiration: models.Validity{Type: models.Duration, Duration: (models.TimeDuration)(lifespanCADur)},
		ProfileID:    profile.ID,
		Metadata:     map[string]any{},
	})
	require.NoError(t, err, "could not create CA")

	// Create DMS
	dms, err := dmsMgr.Service.CreateDMS(ctx, services.CreateDMSInput{
		ID:       uuid.NewString(),
		Name:     "TestDMS",
		Metadata: map[string]any{},
		Settings: models.DMSSettings{
			EnrollmentSettings: models.EnrollmentSettings{
				EnrollmentProtocol: models.EST,
				EnrollmentCA:       testCA.ID,
			},
			ReEnrollmentSettings: models.ReEnrollmentSettings{
				ReEnrollmentDelta:           models.TimeDuration(time.Hour),
				PreventiveReEnrollmentDelta: models.TimeDuration(time.Minute * 3),
				CriticalReEnrollmentDelta:   models.TimeDuration(time.Minute * 2),
			},
		},
	})
	require.NoError(t, err, "could not create DMS")

	// Create device
	deviceID := uuid.NewString()
	device, err := testServers.DeviceManager.Service.CreateDevice(ctx, services.CreateDeviceInput{
		ID:        deviceID,
		Alias:     "test-device",
		Icon:      "BiSolidCreditCardFront",
		IconColor: "#25ee32",
		DMSID:     dms.ID,
	})
	require.NoError(t, err, "could not create device")

	// Issue certificate
	key, _ := chelpers.GenerateECDSAKey(elliptic.P224())
	csr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, key)
	cert, err := testServers.CA.Service.SignCertificate(ctx, services.SignCertificateInput{
		CAID:              testCA.ID,
		CertRequest:       (*models.X509CertificateRequest)(csr),
		IssuanceProfileID: testCA.ProfileID,
	})
	require.NoError(t, err, "could not sign certificate")

	// Bind certificate to device directly using BindIdentityToDevice
	output, err := dmsMgr.Service.BindIdentityToDevice(ctx, services.BindIdentityToDeviceInput{
		DeviceID:                device.ID,
		CertificateSerialNumber: cert.SerialNumber,
		BindMode:                models.DeviceEventTypeProvisioned,
	})
	require.NoError(t, err, "should bind identity to device")
	require.NotNil(t, output, "output should not be nil")

	// Get device and verify expiration date
	deviceAfterBind, err := testServers.DeviceManager.Service.GetDeviceByID(ctx, services.GetDeviceByIDInput{
		ID: deviceID,
	})
	require.NoError(t, err, "should get device by ID")
	require.NotNil(t, deviceAfterBind.IdentitySlot, "identity slot should not be nil")
	require.NotNil(t, deviceAfterBind.IdentitySlot.ExpirationDate,
		"expiration date should be set after binding")

	// Verify expiration date matches certificate (compare Unix timestamps to avoid timezone issues)
	assert.Equal(t, cert.ValidTo.Unix(), deviceAfterBind.IdentitySlot.ExpirationDate.Unix(),
		"expiration date should match certificate ValidTo")
}

func TestBindIdentityToDevice_MultipleBindings_TracksLatestExpiration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	dmsMgr, testServers, err := StartDMSManagerServiceTestServer(t, false)
	require.NoError(t, err, "could not create DMS Manager test server")

	// Create CA
	lifespanCADur, _ := models.ParseDuration("1y")
	issuanceCADur, _ := models.ParseDuration("30d")

	profile, err := testServers.CA.Service.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Validity: models.Validity{Type: models.Duration, Duration: (models.TimeDuration)(issuanceCADur)},
		},
	})
	require.NoError(t, err, "could not create issuance profile")

	testCA, err := testServers.CA.Service.CreateCA(ctx, services.CreateCAInput{
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 224},
		Subject:      models.Subject{CommonName: "test-ca"},
		CAExpiration: models.Validity{Type: models.Duration, Duration: (models.TimeDuration)(lifespanCADur)},
		ProfileID:    profile.ID,
		Metadata:     map[string]any{},
	})
	require.NoError(t, err, "could not create CA")

	// Create DMS
	dms, err := dmsMgr.Service.CreateDMS(ctx, services.CreateDMSInput{
		ID:       uuid.NewString(),
		Name:     "TestDMS",
		Metadata: map[string]any{},
		Settings: models.DMSSettings{
			EnrollmentSettings: models.EnrollmentSettings{
				EnrollmentProtocol: models.EST,
				EnrollmentCA:       testCA.ID,
			},
			ReEnrollmentSettings: models.ReEnrollmentSettings{
				ReEnrollmentDelta:           models.TimeDuration(time.Hour),
				PreventiveReEnrollmentDelta: models.TimeDuration(time.Minute * 3),
				CriticalReEnrollmentDelta:   models.TimeDuration(time.Minute * 2),
			},
		},
	})
	require.NoError(t, err, "could not create DMS")

	// Create device
	deviceID := uuid.NewString()
	device, err := testServers.DeviceManager.Service.CreateDevice(ctx, services.CreateDeviceInput{
		ID:        deviceID,
		Alias:     "test-device",
		Icon:      "BiSolidCreditCardFront",
		IconColor: "#25ee32",
		DMSID:     dms.ID,
	})
	require.NoError(t, err, "could not create device")

	// First binding
	key1, _ := chelpers.GenerateECDSAKey(elliptic.P224())
	csr1, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, key1)
	cert1, err := testServers.CA.Service.SignCertificate(ctx, services.SignCertificateInput{
		CAID:              testCA.ID,
		CertRequest:       (*models.X509CertificateRequest)(csr1),
		IssuanceProfileID: testCA.ProfileID,
	})
	require.NoError(t, err, "could not sign first certificate")

	_, err = dmsMgr.Service.BindIdentityToDevice(ctx, services.BindIdentityToDeviceInput{
		DeviceID:                device.ID,
		CertificateSerialNumber: cert1.SerialNumber,
		BindMode:                models.DeviceEventTypeProvisioned,
	})
	require.NoError(t, err, "first binding should succeed")

	deviceAfterFirst, err := testServers.DeviceManager.Service.GetDeviceByID(ctx, services.GetDeviceByIDInput{
		ID: deviceID,
	})
	require.NoError(t, err, "should get device after first binding")
	firstExpiration := *deviceAfterFirst.IdentitySlot.ExpirationDate

	// Wait to ensure different certificate timestamps
	time.Sleep(2 * time.Second)

	// Second binding (simulating renewal)
	key2, _ := chelpers.GenerateECDSAKey(elliptic.P224())
	csr2, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, key2)
	cert2, err := testServers.CA.Service.SignCertificate(ctx, services.SignCertificateInput{
		CAID:              testCA.ID,
		CertRequest:       (*models.X509CertificateRequest)(csr2),
		IssuanceProfileID: testCA.ProfileID,
	})
	require.NoError(t, err, "could not sign second certificate")

	_, err = dmsMgr.Service.BindIdentityToDevice(ctx, services.BindIdentityToDeviceInput{
		DeviceID:                device.ID,
		CertificateSerialNumber: cert2.SerialNumber,
		BindMode:                models.DeviceEventTypeRenewed,
	})
	require.NoError(t, err, "second binding should succeed")

	// Verify expiration is updated to track the latest certificate
	deviceAfterSecond, err := testServers.DeviceManager.Service.GetDeviceByID(ctx, services.GetDeviceByIDInput{
		ID: deviceID,
	})
	require.NoError(t, err, "should get device after second binding")

	require.NotNil(t, deviceAfterSecond.IdentitySlot.ExpirationDate,
		"expiration date should still be set")
	secondExpiration := *deviceAfterSecond.IdentitySlot.ExpirationDate

	// Verify active version increased
	assert.Equal(t, 1, deviceAfterSecond.IdentitySlot.ActiveVersion,
		"active version should be incremented")

	// Verify expiration matches the latest certificate (compare Unix timestamps to avoid timezone issues)
	assert.Equal(t, cert2.ValidTo.Unix(), secondExpiration.Unix(),
		"expiration should match second certificate")

	// Verify expiration changed from first to second
	assert.NotEqual(t, firstExpiration, secondExpiration,
		"expiration should be updated")

	// Verify second expiration is later than first
	assert.True(t, secondExpiration.After(firstExpiration),
		"second expiration should be later than first")
}
