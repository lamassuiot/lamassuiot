package assemblers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/globalsign/est"
	"github.com/google/uuid"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	identityextractors "github.com/lamassuiot/lamassuiot/v2/pkg/routes/middlewares/identity-extractors"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
	"golang.org/x/crypto/ocsp"
)

func StartDMSManagerServiceTestServer(t *testing.T, withEventBus bool) (*DMSManagerTestServer, *TestServer, error) {
	var err error
	eventBusConf := &TestEventBusConfig{
		config: config.EventBusEngine{
			Enabled: false,
		},
	}
	if withEventBus {
		eventBusConf, err = PrepareRabbitMQForTest()
		if err != nil {
			t.Fatalf("could not prepare RabbitMQ test server: %s", err)
		}
	}

	storageConfig, err := PreparePostgresForTest([]string{"ca", "devicemanager", "dmsmanager"})
	if err != nil {
		t.Fatalf("could not prepare Postgres test server: %s", err)
	}
	cryptoConfig := PrepareCryptoEnginesForTest([]CryptoEngine{GOLANG})
	testServer, err := AssembleServices(storageConfig, eventBusConf, cryptoConfig, []Service{CA, DEVICE_MANAGER, DMS_MANAGER})
	if err != nil {
		t.Fatalf("could not assemble Server with HTTP server: %s", err)
	}
	err = testServer.BeforeEach()
	if err != nil {
		t.Fatalf("could not run 'BeforeEach' cleanup func in test case: %s", err)
	}

	t.Cleanup(testServer.AfterSuite)

	return testServer.DMSManager, testServer, nil
}

func TestCreateDMS(t *testing.T) {
	dmsMgr, _, err := StartDMSManagerServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create DMS Manager test server: %s", err)
	}

	dmsSample := services.CreateDMSInput{
		ID:   "1234-5678",
		Name: "MyIotFleet",
	}
	dms, err := dmsMgr.HttpDeviceManagerSDK.CreateDMS(context.Background(), dmsSample)
	if err != nil {
		t.Fatalf("could not create DMS: %s", err)
	}

	checkDMS(t, dms, dmsSample)
	_, err = dmsMgr.Service.CreateDMS(context.Background(), dmsSample)
	if err == nil {
		t.Fatalf("duplicate dms creation should fail")
	}
}

func TestESTEnroll(t *testing.T) {
	// t.Parallel()
	ctx := context.Background()

	dmsMgr, testServers, err := StartDMSManagerServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create DMS Manager test server: %s", err)
	}

	createCA := func(name string, lifespan string, issuance string) (*models.CACertificate, error) {
		lifespanCABootDur, _ := models.ParseDuration(lifespan)
		issuanceCABootDur, _ := models.ParseDuration(issuance)
		return testServers.CA.Service.CreateCA(context.Background(), services.CreateCAInput{
			KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 224},
			Subject:            models.Subject{CommonName: name},
			CAExpiration:       models.Expiration{Type: models.Duration, Duration: (*models.TimeDuration)(&lifespanCABootDur)},
			IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: (*models.TimeDuration)(&issuanceCABootDur)},
			Metadata:           map[string]any{},
		})
	}

	createDMS := func(modifier func(in *services.CreateDMSInput)) (*models.DMS, error) {
		input := services.CreateDMSInput{
			ID:       uuid.NewString(),
			Name:     "MyIotFleet",
			Metadata: map[string]any{},
			Settings: models.DMSSettings{
				EnrollmentSettings: models.EnrollmentSettings{
					EnrollmentProtocol: models.EST,
					EnrollmentOptionsESTRFC7030: models.EnrollmentOptionsESTRFC7030{
						AuthMode: models.ESTAuthMode(identityextractors.IdentityExtractorClientCertificate),
						AuthOptionsMTLS: models.AuthOptionsClientCertificate{
							ChainLevelValidation: -1,
							ValidationCAs:        []string{},
						},
					},
					DeviceProvisionProfile: models.DeviceProvisionProfile{
						Icon:      "BiSolidCreditCardFront",
						IconColor: "#25ee32-#222222",
						Metadata:  map[string]any{},
						Tags:      []string{"iot", "testdms", "cloud"},
					},
					RegistrationMode:            models.JITP,
					EnableReplaceableEnrollment: true,
				},
				ReEnrollmentSettings: models.ReEnrollmentSettings{
					AdditionalValidationCAs:     []string{},
					ReEnrollmentDelta:           models.TimeDuration(time.Hour),
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
		}

		modifier(&input)

		return dmsMgr.Service.CreateDMS(context.Background(), input)
	}

	var testcases = []struct {
		name        string
		run         func() (caCert *x509.Certificate, cert *x509.Certificate, key any, err error)
		resultCheck func(caCert *x509.Certificate, cert *x509.Certificate, key any, err error)
	}{
		{
			name: "OK/ECDSA",
			run: func() (caCert *x509.Certificate, cert *x509.Certificate, key any, err error) {
				bootstrapCA, err := createCA("boot", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create bootstrap CA: %s", err)
				}

				enrollCA, err := createCA("enroll", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create Enrollment CA: %s", err)
				}

				dms, err := createDMS(func(in *services.CreateDMSInput) {
					in.Settings.EnrollmentSettings.EnrollmentCA = enrollCA.ID
					in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsMTLS.ValidationCAs = []string{
						bootstrapCA.ID,
					}
				})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}

				bootKey, _ := helpers.GenerateECDSAKey(elliptic.P224())
				bootCsr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
				bootCrt, err := testServers.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:         bootstrapCA.ID,
					CertRequest:  (*models.X509CertificateRequest)(bootCsr),
					SignVerbatim: true,
				})
				if err != nil {
					t.Fatalf("could not sign Bootstrap Certificate: %s", err)
				}

				estCli := est.Client{
					Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
					AdditionalPathSegment: dms.ID,
					Certificates:          []*x509.Certificate{(*x509.Certificate)(bootCrt.Certificate)},
					PrivateKey:            bootKey,
					InsecureSkipVerify:    true,
				}

				deviceID := fmt.Sprintf("enrolled-device-%s", uuid.NewString())
				enrollKey, _ := helpers.GenerateECDSAKey(elliptic.P224())
				enrollCSR, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

				enrollCRT, err := estCli.Enroll(context.Background(), enrollCSR)
				if err != nil {
					t.Fatalf("unexpected error while enrolling: %s", err)
				}

				return (*x509.Certificate)(enrollCA.Certificate.Certificate), enrollCRT, enrollKey, nil
			},
			resultCheck: func(caCert, cert *x509.Certificate, key any, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}

				priv, ok := key.(*ecdsa.PrivateKey)
				if !ok {
					t.Fatalf("could not cast priv key into ECDSA")
				}

				valid, err := helpers.ValidateCertAndPrivKey(cert, nil, priv)
				if err != nil {
					t.Fatalf("could not validate cert and key. Got error: %s", err)
				}

				if !valid {
					t.Fatalf("private key does not match public key")
				}

				if err = helpers.ValidateCertificate(caCert, cert, true); err != nil {
					t.Fatalf("could not validate certificate with CA: %s", err)
				}
			},
		},
		{
			name: "OK/RSA",
			run: func() (caCert, cert *x509.Certificate, key any, err error) {
				bootstrapCA, err := createCA("boot", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create bootstrap CA: %s", err)
				}

				enrollCA, err := createCA("enroll", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create Enrollment CA: %s", err)
				}

				dms, err := createDMS(func(in *services.CreateDMSInput) {
					in.Settings.EnrollmentSettings.EnrollmentCA = enrollCA.ID
					in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsMTLS.ValidationCAs = []string{
						bootstrapCA.ID,
					}
				})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}

				bootKey, _ := helpers.GenerateECDSAKey(elliptic.P224())
				bootCsr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
				bootCrt, err := testServers.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:         bootstrapCA.ID,
					CertRequest:  (*models.X509CertificateRequest)(bootCsr),
					SignVerbatim: true,
				})
				if err != nil {
					t.Fatalf("could not sign Bootstrap Certificate: %s", err)
				}

				estCli := est.Client{
					Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
					AdditionalPathSegment: dms.ID,
					Certificates:          []*x509.Certificate{(*x509.Certificate)(bootCrt.Certificate)},
					PrivateKey:            bootKey,
					InsecureSkipVerify:    true,
				}

				deviceID := fmt.Sprintf("enrolled-device-%s", uuid.NewString())
				enrollKey, _ := helpers.GenerateRSAKey(2048)
				enrollCSR, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

				enrollCRT, err := estCli.Enroll(context.Background(), enrollCSR)
				if err != nil {
					t.Fatalf("unexpected error while enrolling: %s", err)
				}

				return (*x509.Certificate)(enrollCA.Certificate.Certificate), enrollCRT, enrollKey, nil
			},
			resultCheck: func(caCert *x509.Certificate, cert *x509.Certificate, key any, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}

				priv, ok := key.(*rsa.PrivateKey)
				if !ok {
					t.Fatal("could not cast priv key into RSA")
				}

				valid, err := helpers.ValidateCertAndPrivKey(cert, priv, nil)
				if err != nil {
					t.Fatalf("could not validate cert and key. Got error: %s", err)
				}

				if !valid {
					t.Fatalf("private key does not match public key")
				}

				if err = helpers.ValidateCertificate(caCert, cert, true); err != nil {
					t.Fatalf("could not validate certificate with CA: %s", err)
				}
			},
		},
		{
			name: "OK/PreRegistration",
			run: func() (caCert, cert *x509.Certificate, key any, err error) {
				bootstrapCA, err := createCA("boot", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create bootstrap CA: %s", err)
				}

				enrollCA, err := createCA("enroll", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create Enrollment CA: %s", err)
				}

				dms, err := createDMS(func(in *services.CreateDMSInput) {
					in.Settings.EnrollmentSettings.RegistrationMode = models.PreRegistration
					in.Settings.EnrollmentSettings.EnrollmentCA = enrollCA.ID
					in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsMTLS.ValidationCAs = []string{
						bootstrapCA.ID,
					}
				})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}

				bootKey, _ := helpers.GenerateECDSAKey(elliptic.P224())
				bootCsr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
				bootCrt, err := testServers.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:         bootstrapCA.ID,
					CertRequest:  (*models.X509CertificateRequest)(bootCsr),
					SignVerbatim: true,
				})
				if err != nil {
					t.Fatalf("could not sign Bootstrap Certificate: %s", err)
				}

				estCli := est.Client{
					Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
					AdditionalPathSegment: dms.ID,
					Certificates:          []*x509.Certificate{(*x509.Certificate)(bootCrt.Certificate)},
					PrivateKey:            bootKey,
					InsecureSkipVerify:    true,
				}

				deviceID := fmt.Sprintf("enrolled-device-%s", uuid.NewString())
				enrollKey, _ := helpers.GenerateRSAKey(2048)
				enrollCSR, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

				_, err = testServers.DeviceManager.Service.CreateDevice(ctx, services.CreateDeviceInput{
					ID:        deviceID,
					Alias:     deviceID,
					Tags:      []string{},
					Metadata:  map[string]any{},
					DMSID:     dms.ID,
					Icon:      "test2",
					IconColor: "#000001",
				})
				if err != nil {
					t.Fatalf("could not register device: %s", err)
				}

				enrollCRT, err := estCli.Enroll(context.Background(), enrollCSR)
				if err != nil {
					t.Fatalf("unexpected error while enrolling: %s", err)
				}

				return (*x509.Certificate)(enrollCA.Certificate.Certificate), enrollCRT, enrollKey, nil
			},
			resultCheck: func(caCert *x509.Certificate, cert *x509.Certificate, key any, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}

				priv, ok := key.(*rsa.PrivateKey)
				if !ok {
					t.Fatalf("could not cast priv key into RSA")
				}

				valid, err := helpers.ValidateCertAndPrivKey(cert, priv, nil)
				if err != nil {
					t.Fatalf("could not validate cert and key. Got error: %s", err)
				}

				if !valid {
					t.Fatalf("private key does not match public key")
				}

				if err = helpers.ValidateCertificate(caCert, cert, true); err != nil {
					t.Fatalf("could not validate certificate with CA: %s", err)
				}
			},
		},
		{
			name: "Err/PreRegistrationWithUnregisteredDevice",
			run: func() (caCert, cert *x509.Certificate, key any, err error) {
				bootstrapCA, err := createCA("boot", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create bootstrap CA: %s", err)
				}

				enrollCA, err := createCA("enroll", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create Enrollment CA: %s", err)
				}

				dms, err := createDMS(func(in *services.CreateDMSInput) {
					in.Settings.EnrollmentSettings.RegistrationMode = models.PreRegistration
					in.Settings.EnrollmentSettings.EnrollmentCA = enrollCA.ID
					in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsMTLS.ValidationCAs = []string{
						bootstrapCA.ID,
					}
				})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}

				bootKey, _ := helpers.GenerateECDSAKey(elliptic.P224())
				bootCsr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
				bootCrt, err := testServers.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:         bootstrapCA.ID,
					CertRequest:  (*models.X509CertificateRequest)(bootCsr),
					SignVerbatim: true,
				})
				if err != nil {
					t.Fatalf("could not sign Bootstrap Certificate: %s", err)
				}

				estCli := est.Client{
					Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
					AdditionalPathSegment: dms.ID,
					Certificates:          []*x509.Certificate{(*x509.Certificate)(bootCrt.Certificate)},
					PrivateKey:            bootKey,
					InsecureSkipVerify:    true,
				}

				deviceID := fmt.Sprintf("enrolled-device-%s", uuid.NewString())
				enrollKey, _ := helpers.GenerateRSAKey(2048)
				enrollCSR, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

				_, err = estCli.Enroll(context.Background(), enrollCSR)
				return nil, nil, nil, err
			},
			resultCheck: func(caCert, cert *x509.Certificate, key any, err error) {
				if err == nil {
					t.Fatalf("expected error. Got none")
				}

				expectedErr := "device not preregistered"
				if !strings.Contains(err.Error(), expectedErr) {
					t.Fatalf("error should contain '%s'. Got error %s", expectedErr, err.Error())
				}
			},
		},
		{
			name: "Err/UnauthorizedValidationCA",
			run: func() (caCert, cert *x509.Certificate, key any, err error) {
				bootstrapCA, err := createCA("boot", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create bootstrap CA: %s", err)
				}

				enrollCA, err := createCA("enroll", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create Enrollment CA: %s", err)
				}

				dms, err := createDMS(func(in *services.CreateDMSInput) {
					in.Settings.EnrollmentSettings.EnrollmentCA = enrollCA.ID
					in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsMTLS.ValidationCAs = []string{
						bootstrapCA.ID,
					}
				})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}

				fakeKey, _ := helpers.GenerateRSAKey(2048)
				fakeCert, _ := helpers.GenerateSelfSignedCertificate(fakeKey, "my-fake-cert")
				estCli := est.Client{
					Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
					AdditionalPathSegment: dms.ID,
					Certificates:          []*x509.Certificate{fakeCert},
					PrivateKey:            fakeKey,
					InsecureSkipVerify:    true,
				}

				deviceID := fmt.Sprintf("enrolled-device-%s", uuid.NewString())
				enrollKey, _ := helpers.GenerateRSAKey(2048)
				enrollCSR, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

				_, err = estCli.Enroll(context.Background(), enrollCSR)
				return nil, nil, nil, err
			},
			resultCheck: func(caCert, cert *x509.Certificate, key any, err error) {
				if err == nil {
					t.Fatalf("expected error. Got none")
				}

				expectedErr := "invalid certificate"
				if !strings.Contains(err.Error(), expectedErr) {
					t.Fatalf("error should contain '%s'. Got error %s", expectedErr, err.Error())
				}
			},
		},
		{
			name: "Err/ExpiredCertificate",
			run: func() (caCert, cert *x509.Certificate, key any, err error) {
				bootstrapCA, err := createCA("boot", "1y", "3s")
				if err != nil {
					t.Fatalf("could not create bootstrap CA: %s", err)
				}

				enrollCA, err := createCA("enroll", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create Enrollment CA: %s", err)
				}

				dms, err := createDMS(func(in *services.CreateDMSInput) {
					in.Settings.EnrollmentSettings.EnrollmentCA = enrollCA.ID
					in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsMTLS.ValidationCAs = []string{
						bootstrapCA.ID,
					}
				})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}

				bootKey, _ := helpers.GenerateECDSAKey(elliptic.P224())
				bootCsr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
				bootCrt, err := testServers.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:         bootstrapCA.ID,
					CertRequest:  (*models.X509CertificateRequest)(bootCsr),
					SignVerbatim: true,
				})
				if err != nil {
					t.Fatalf("could not sign Bootstrap Certificate: %s", err)
				}

				estCli := est.Client{
					Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
					AdditionalPathSegment: dms.ID,
					Certificates:          []*x509.Certificate{(*x509.Certificate)(bootCrt.Certificate)},
					PrivateKey:            bootKey,
					InsecureSkipVerify:    true,
				}

				deviceID := fmt.Sprintf("enrolled-device-%s", uuid.NewString())
				enrollKey, _ := helpers.GenerateRSAKey(2048)
				enrollCSR, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

				time.Sleep(3 * time.Second)

				_, err = estCli.Enroll(context.Background(), enrollCSR)
				return nil, nil, nil, err
			},
			resultCheck: func(caCert, cert *x509.Certificate, key any, err error) {
				if err == nil {
					t.Fatalf("expected error. Got none")
				}

				expectedErr := "invalid certificate"
				if !strings.Contains(err.Error(), expectedErr) {
					t.Fatalf("error should contain '%s'. Got error %s", expectedErr, err.Error())
				}
			},
		},
		{
			name: "Err/RevokedCertificate",
			run: func() (caCert, cert *x509.Certificate, key any, err error) {
				bootstrapCA, err := createCA("boot", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create bootstrap CA: %s", err)
				}

				enrollCA, err := createCA("enroll", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create Enrollment CA: %s", err)
				}

				dms, err := createDMS(func(in *services.CreateDMSInput) {
					in.Settings.EnrollmentSettings.EnrollmentCA = enrollCA.ID
					in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsMTLS.ValidationCAs = []string{
						bootstrapCA.ID,
					}
				})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}

				bootKey, _ := helpers.GenerateECDSAKey(elliptic.P224())
				bootCsr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
				bootCrt, err := testServers.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:         bootstrapCA.ID,
					CertRequest:  (*models.X509CertificateRequest)(bootCsr),
					SignVerbatim: true,
				})
				if err != nil {
					t.Fatalf("could not sign Bootstrap Certificate: %s", err)
				}

				_, err = testServers.CA.Service.UpdateCertificateStatus(context.Background(), services.UpdateCertificateStatusInput{
					SerialNumber:     bootCrt.SerialNumber,
					NewStatus:        models.StatusRevoked,
					RevocationReason: ocsp.KeyCompromise,
				})
				if err != nil {
					t.Fatalf("could not revoke Bootstrap Certificate: %s", err)
				}

				estCli := est.Client{
					Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
					AdditionalPathSegment: dms.ID,
					Certificates:          []*x509.Certificate{(*x509.Certificate)(bootCrt.Certificate)},
					PrivateKey:            bootKey,
					InsecureSkipVerify:    true,
				}

				deviceID := fmt.Sprintf("enrolled-device-%s", uuid.NewString())
				enrollKey, _ := helpers.GenerateRSAKey(2048)
				enrollCSR, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

				_, err = estCli.Enroll(context.Background(), enrollCSR)
				return nil, nil, nil, err
			},
			resultCheck: func(caCert, cert *x509.Certificate, key any, err error) {
				if err == nil {
					t.Fatalf("expected error. Got none")
				}

				expectedErr := "certificate is revoked"
				if !strings.Contains(err.Error(), expectedErr) {
					t.Fatalf("error should contain '%s'. Got error %s", expectedErr, err.Error())
				}
			},
		},
		// TODO: Find a way of testing this. As of now, this causes a problem since the Testing Instance is launched under
		// dev.lamassu.test domain. Then the DMS requests an OCSP/CRL request to https://dev.lamassu.test/api/va/crl/xxxx which
		// is unreachable. We need a way of proxying dev.lamassu.test => localhost:xxxx (each test has a random port).
		// {
		// 	name: "Err/ExternalRevokedCertificate",
		// 	run: func() (caCert, cert *x509.Certificate, key any, err error) {
		// 		_, externalTestServers, err := StartDMSManagerServiceTestServer(t, false)
		// 		if err != nil {
		// 			t.Fatalf("could not create Second DMS Manager test server: %s", err)
		// 		}

		// 		lifespanCABootDur, _ := models.ParseDuration("1y")
		// 		issuanceCABootDur, _ := models.ParseDuration("1m")
		// 		bootstrapCA, err := externalTestServers.CA.Service.CreateCA(context.Background(), services.CreateCAInput{
		// 			KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 224},
		// 			Subject:            models.Subject{CommonName: "ExternalCA"},
		// 			CAExpiration:       models.Expiration{Type: models.Duration, Duration: (*models.TimeDuration)(&lifespanCABootDur)},
		// 			IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: (*models.TimeDuration)(&issuanceCABootDur)},
		// 			Metadata:           map[string]any{},
		// 		})
		// 		if err != nil {
		// 			t.Fatalf("could not create external Bootstrap CA: %s", err)
		// 		}

		// 		importedBootstrapCA, err := testServers.CA.Service.ImportCA(context.Background(), services.ImportCAInput{
		// 			ID:                 fmt.Sprintf("my-external-CA-%s", uuid.NewString()),
		// 			CAType:             models.CertificateTypeExternal,
		// 			IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: (*models.TimeDuration)(&issuanceCABootDur)},
		// 			CACertificate:      bootstrapCA.Certificate.Certificate,
		// 		})
		// 		if err != nil {
		// 			t.Fatalf("could not import external Bootstrap CA: %s", err)
		// 		}

		// 		enrollCA, err := createCA("enroll", "1y", "1m")
		// 		if err != nil {
		// 			t.Fatalf("could not create Enrollment CA: %s", err)
		// 		}

		// 		dms, err := createDMS(func(in *services.CreateDMSInput) {
		// 			in.Settings.EnrollmentSettings.EnrollmentCA = enrollCA.ID
		// 			in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsMTLS.ValidationCAs = []string{
		// 				importedBootstrapCA.ID,
		// 			}
		// 		})
		// 		if err != nil {
		// 			t.Fatalf("could not create DMS: %s", err)
		// 		}

		// 		bootKey, _ := helpers.GenerateECDSAKey(elliptic.P224())
		// 		bootCsr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
		// 		bootCrt, err := externalTestServers.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
		// 			CAID:         bootstrapCA.ID,
		// 			CertRequest:  (*models.X509CertificateRequest)(bootCsr),
		// 			SignVerbatim: true,
		// 		})
		// 		if err != nil {
		// 			t.Fatalf("could not sign Bootstrap Certificate: %s", err)
		// 		}

		// 		_, err = externalTestServers.CA.Service.UpdateCertificateStatus(context.Background(), services.UpdateCertificateStatusInput{
		// 			SerialNumber:     bootCrt.SerialNumber,
		// 			NewStatus:        models.StatusRevoked,
		// 			RevocationReason: ocsp.KeyCompromise,
		// 		})
		// 		if err != nil {
		// 			t.Fatalf("could not revoke Bootstrap Certificate: %s", err)
		// 		}

		// 		estCli := est.Client{
		// 			Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
		// 			AdditionalPathSegment: dms.ID,
		// 			Certificates:          []*x509.Certificate{(*x509.Certificate)(bootCrt.Certificate)},
		// 			PrivateKey:            bootKey,
		// 			InsecureSkipVerify:    true,
		// 		}

		// 		deviceID := fmt.Sprintf("enrolled-device-%s", uuid.NewString())
		// 		enrollKey, _ := helpers.GenerateRSAKey(2048)
		// 		enrollCSR, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

		// 		_, err = estCli.Enroll(context.Background(), enrollCSR)
		// 		return nil, nil, nil, err
		// 	},
		// 	resultCheck: func(caCert, cert *x509.Certificate, key any, err error) {
		// 		if err == nil {
		// 			t.Fatalf("expected error. Got none")
		// 		}

		// 		expectedErr := "certificate is revoked"
		// 		if !strings.Contains(err.Error(), expectedErr) {
		// 			t.Fatalf("error should contain '%s'. Got error %s", expectedErr, err.Error())
		// 		}
		// 	},
		// },
		{
			name: "OK/PEMOutput",
			run: func() (caCert, cert *x509.Certificate, key any, err error) {
				bootstrapCA, err := createCA("boot", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create bootstrap CA: %s", err)
				}

				enrollCA, err := createCA("enroll", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create Enrollment CA: %s", err)
				}

				dms, err := createDMS(func(in *services.CreateDMSInput) {
					in.Settings.EnrollmentSettings.EnrollmentCA = enrollCA.ID
					in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsMTLS.ValidationCAs = []string{
						bootstrapCA.ID,
					}
				})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}

				bootKey, _ := helpers.GenerateECDSAKey(elliptic.P224())
				bootCsr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
				bootCrt, err := testServers.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:         bootstrapCA.ID,
					CertRequest:  (*models.X509CertificateRequest)(bootCsr),
					SignVerbatim: true,
				})
				if err != nil {
					t.Fatalf("could not sign Bootstrap Certificate: %s", err)
				}

				estCli := pemESTClient{
					baseEndpoint: fmt.Sprintf("https://localhost:%d/.well-known/est/%s", dmsMgr.Port, dms.ID),
					cert:         (*x509.Certificate)(bootCrt.Certificate),
					key:          bootKey,
				}

				deviceID := fmt.Sprintf("enrolled-device-%s", uuid.NewString())
				enrollKey, _ := helpers.GenerateRSAKey(2048)
				enrollCSR, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

				enrollCRT, err := estCli.Enroll(enrollCSR)
				if err != nil {
					t.Fatalf("unexpected error while enrolling: %s", err)
				}

				return (*x509.Certificate)(enrollCA.Certificate.Certificate), enrollCRT, enrollKey, nil
			},
			resultCheck: func(caCert *x509.Certificate, cert *x509.Certificate, key any, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}

				priv, ok := key.(*rsa.PrivateKey)
				if !ok {
					t.Fatal("could not cast priv key into RSA")
				}

				valid, err := helpers.ValidateCertAndPrivKey(cert, priv, nil)
				if err != nil {
					t.Fatalf("could not validate cert and key. Got error: %s", err)
				}

				if !valid {
					t.Fatalf("private key does not match public key")
				}

				if err = helpers.ValidateCertificate(caCert, cert, true); err != nil {
					t.Fatalf("could not validate certificate with CA: %s", err)
				}
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			tc.resultCheck(tc.run())
		})
	}
}

func TestESTServerKeyGen(t *testing.T) {
	// t.Parallel()
	ctx := context.Background()

	dmsMgr, testServers, err := StartDMSManagerServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create DMS Manager test server: %s", err)
	}

	createCA := func(name string, lifespan string, issuance string) (*models.CACertificate, error) {
		lifespanCABootDur, _ := models.ParseDuration(lifespan)
		issuanceCABootDur, _ := models.ParseDuration(issuance)
		return testServers.CA.Service.CreateCA(ctx, services.CreateCAInput{
			KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 224},
			Subject:            models.Subject{CommonName: name},
			CAExpiration:       models.Expiration{Type: models.Duration, Duration: (*models.TimeDuration)(&lifespanCABootDur)},
			IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: (*models.TimeDuration)(&issuanceCABootDur)},
			Metadata:           map[string]any{},
		})
	}

	createDMS := func(modifier func(in *services.CreateDMSInput)) (*models.DMS, error) {
		input := services.CreateDMSInput{
			ID:       uuid.NewString(),
			Name:     "MyIotFleet",
			Metadata: map[string]any{},
			Settings: models.DMSSettings{
				ServerKeyGen: &models.ServerKeyGenSettings{
					Enabled: true,
					Key: models.ServerKeyGenKey{
						Type: models.KeyType(x509.RSA),
						Bits: 2048,
					},
				},
				EnrollmentSettings: models.EnrollmentSettings{
					EnrollmentProtocol: models.EST,
					EnrollmentOptionsESTRFC7030: models.EnrollmentOptionsESTRFC7030{
						AuthMode: models.ESTAuthMode(identityextractors.IdentityExtractorClientCertificate),
						AuthOptionsMTLS: models.AuthOptionsClientCertificate{
							ChainLevelValidation: -1,
							ValidationCAs:        []string{},
						},
					},
					DeviceProvisionProfile: models.DeviceProvisionProfile{
						Icon:      "BiSolidCreditCardFront",
						IconColor: "#25ee32-#222222",
						Metadata:  map[string]any{},
						Tags:      []string{"iot", "testdms", "cloud"},
					},
					RegistrationMode:            models.JITP,
					EnableReplaceableEnrollment: true,
				},
				ReEnrollmentSettings: models.ReEnrollmentSettings{
					AdditionalValidationCAs:     []string{},
					ReEnrollmentDelta:           models.TimeDuration(time.Hour),
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
		}

		modifier(&input)

		return dmsMgr.Service.CreateDMS(ctx, input)
	}

	var testcases = []struct {
		name        string
		run         func() (caCert *x509.Certificate, cert *x509.Certificate, key any, err error)
		resultCheck func(caCert *x509.Certificate, cert *x509.Certificate, key any, err error)
	}{
		{
			name: "OK/ECDSA-256",
			run: func() (caCert *x509.Certificate, cert *x509.Certificate, key any, err error) {
				bootstrapCA, err := createCA("boot", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create bootstrap CA: %s", err)
				}

				enrollCA, err := createCA("enroll", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create Enrollment CA: %s", err)
				}

				dms, err := createDMS(func(in *services.CreateDMSInput) {
					in.Settings.ServerKeyGen.Key = models.ServerKeyGenKey{
						Type: models.KeyType(x509.ECDSA),
						Bits: 256,
					}
					in.Settings.EnrollmentSettings.EnrollmentCA = enrollCA.ID
					in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsMTLS.ValidationCAs = []string{
						bootstrapCA.ID,
					}
				})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}

				bootKey, _ := helpers.GenerateECDSAKey(elliptic.P224())
				bootCsr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
				bootCrt, err := testServers.CA.Service.SignCertificate(ctx, services.SignCertificateInput{
					CAID:         bootstrapCA.ID,
					CertRequest:  (*models.X509CertificateRequest)(bootCsr),
					SignVerbatim: true,
				})
				if err != nil {
					t.Fatalf("could not sign Bootstrap Certificate: %s", err)
				}

				estCli := est.Client{
					Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
					AdditionalPathSegment: dms.ID,
					Certificates:          []*x509.Certificate{(*x509.Certificate)(bootCrt.Certificate)},
					PrivateKey:            bootKey,
					InsecureSkipVerify:    true,
				}

				//Generate a "generic" key pair
				genericKey, _ := helpers.GenerateECDSAKey(elliptic.P224())
				enrollCSR, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: "generic-csr"}, genericKey)

				//Replace the CSR subject (it is crucial that the signature of the CSR is not valid due to this change as it is stated in the RFC7030)
				//the server should not check the consistency/validity of the signature
				deviceID := fmt.Sprintf("skeygen-enrolled-device-%s", uuid.NewString())
				enrollCSR.Subject = pkix.Name{
					CommonName: deviceID,
				}

				enrollCRT, enrollKey, err := estCli.ServerKeyGen(ctx, enrollCSR)
				if err != nil {
					t.Fatalf("unexpected error while enrolling: %s", err)
				}

				serverKeyGen, err := x509.ParsePKCS8PrivateKey(enrollKey)
				if err != nil {
					t.Fatalf("unexpected error while parsing server generated key: %s", err)
				}

				return (*x509.Certificate)(enrollCA.Certificate.Certificate), enrollCRT, serverKeyGen, nil
			},
			resultCheck: func(caCert, cert *x509.Certificate, key any, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}

				serverKeyGen, ok := key.(*ecdsa.PrivateKey)
				if !ok {
					t.Fatalf("unexpected key type. Expected an ECDSA Key")
				}

				if serverKeyGen.Curve != elliptic.P256() {
					t.Fatalf("unexpected key size. Expected an 256 key size")
				}

				valid, err := helpers.ValidateCertAndPrivKey(cert, nil, serverKeyGen)
				if err != nil {
					t.Fatalf("could not validate cert and key. Got error: %s", err)
				}

				if !valid {
					t.Fatalf("private key does not match public key")
				}

				if err = helpers.ValidateCertificate(caCert, cert, true); err != nil {
					t.Fatalf("could not validate certificate with CA: %s", err)
				}
			},
		},
		{
			name: "OK/RSA-3072",
			run: func() (caCert *x509.Certificate, cert *x509.Certificate, key any, err error) {
				bootstrapCA, err := createCA("boot", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create bootstrap CA: %s", err)
				}

				enrollCA, err := createCA("enroll", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create Enrollment CA: %s", err)
				}

				dms, err := createDMS(func(in *services.CreateDMSInput) {
					in.Settings.ServerKeyGen.Key = models.ServerKeyGenKey{
						Type: models.KeyType(x509.RSA),
						Bits: 3072,
					}
					in.Settings.EnrollmentSettings.EnrollmentCA = enrollCA.ID
					in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsMTLS.ValidationCAs = []string{
						bootstrapCA.ID,
					}
				})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}

				bootKey, _ := helpers.GenerateECDSAKey(elliptic.P224())
				bootCsr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
				bootCrt, err := testServers.CA.Service.SignCertificate(ctx, services.SignCertificateInput{
					CAID:         bootstrapCA.ID,
					CertRequest:  (*models.X509CertificateRequest)(bootCsr),
					SignVerbatim: true,
				})
				if err != nil {
					t.Fatalf("could not sign Bootstrap Certificate: %s", err)
				}

				estCli := est.Client{
					Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
					AdditionalPathSegment: dms.ID,
					Certificates:          []*x509.Certificate{(*x509.Certificate)(bootCrt.Certificate)},
					PrivateKey:            bootKey,
					InsecureSkipVerify:    true,
				}

				//Generate a "generic" key pair
				genericKey, _ := helpers.GenerateECDSAKey(elliptic.P224())
				enrollCSR, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: "generic-csr"}, genericKey)

				//Replace the CSR subject (it is crucial that the signature of the CSR is not valid due to this change as it is stated in the RFC7030)
				//the server should not check the consistency/validity of the signature
				deviceID := fmt.Sprintf("skeygen-enrolled-device-%s", uuid.NewString())
				enrollCSR.Subject = pkix.Name{
					CommonName: deviceID,
				}

				enrollCRT, enrollKey, err := estCli.ServerKeyGen(ctx, enrollCSR)
				if err != nil {
					t.Fatalf("unexpected error while enrolling: %s", err)
				}

				serverKeyGen, err := x509.ParsePKCS8PrivateKey(enrollKey)
				if err != nil {
					t.Fatalf("unexpected error while parsing server generated key: %s", err)
				}

				return (*x509.Certificate)(enrollCA.Certificate.Certificate), enrollCRT, serverKeyGen, nil
			},
			resultCheck: func(caCert, cert *x509.Certificate, key any, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}

				serverKeyGen, ok := key.(*rsa.PrivateKey)
				if !ok {
					t.Fatalf("unexpected key type. Expected an ECDSA Key")
				}

				if serverKeyGen.N.BitLen() != 3072 {
					t.Fatalf("unexpected key size. Expected an 256 key size")
				}

				valid, err := helpers.ValidateCertAndPrivKey(cert, serverKeyGen, nil)
				if err != nil {
					t.Fatalf("could not validate cert and key. Got error: %s", err)
				}

				if !valid {
					t.Fatalf("private key does not match public key")
				}

				if err = helpers.ValidateCertificate(caCert, cert, true); err != nil {
					t.Fatalf("could not validate certificate with CA: %s", err)
				}
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			tc.resultCheck(tc.run())
		})
	}
}

func TestESTReEnroll(t *testing.T) {
	// t.Parallel()
	dmsMgr, testServers, err := StartDMSManagerServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create DMS Manager test server: %s", err)
	}

	createCA := func(name string, lifespan string, issuance string) (*models.CACertificate, error) {
		lifespanCABootDur, _ := models.ParseDuration(lifespan)
		issuanceCABootDur, _ := models.ParseDuration(issuance)
		return testServers.CA.Service.CreateCA(context.Background(), services.CreateCAInput{
			KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 224},
			Subject:            models.Subject{CommonName: name},
			CAExpiration:       models.Expiration{Type: models.Duration, Duration: (*models.TimeDuration)(&lifespanCABootDur)},
			IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: (*models.TimeDuration)(&issuanceCABootDur)},
			Metadata:           map[string]any{},
		})
	}

	createDMS := func(modifier func(in *services.CreateDMSInput)) (*models.DMS, error) {
		input := services.CreateDMSInput{
			ID:       uuid.NewString(),
			Name:     "MyIotFleet",
			Metadata: map[string]any{},
			Settings: models.DMSSettings{
				EnrollmentSettings: models.EnrollmentSettings{
					EnrollmentProtocol: models.EST,
					EnrollmentOptionsESTRFC7030: models.EnrollmentOptionsESTRFC7030{
						AuthMode: models.ESTAuthMode(identityextractors.IdentityExtractorClientCertificate),
						AuthOptionsMTLS: models.AuthOptionsClientCertificate{
							ChainLevelValidation: -1,
							ValidationCAs:        []string{},
						},
					},
					DeviceProvisionProfile: models.DeviceProvisionProfile{
						Icon:      "BiSolidCreditCardFront",
						IconColor: "#25ee32-#222222",
						Metadata:  map[string]any{},
						Tags:      []string{"iot", "testdms", "cloud"},
					},
					RegistrationMode:            models.JITP,
					EnableReplaceableEnrollment: true,
				},
				ReEnrollmentSettings: models.ReEnrollmentSettings{
					AdditionalValidationCAs:     []string{},
					ReEnrollmentDelta:           models.TimeDuration(time.Hour),
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
		}

		modifier(&input)

		return dmsMgr.Service.CreateDMS(context.Background(), input)
	}

	prepReenrollScenario := func(dmsModifier func(in *services.CreateDMSInput), enrollDur string) (dms *models.DMS, enrollmentCA, deviceCert *x509.Certificate, deviceKey any) {
		bootstrapCA, err := createCA("boot", "1y", "1m")
		if err != nil {
			t.Fatalf("could not create bootstrap CA: %s", err)
		}

		enrollCA, err := createCA("enroll", "1y", enrollDur)
		if err != nil {
			t.Fatalf("could not create Enrollment CA: %s", err)
		}

		dms, err = createDMS(func(in *services.CreateDMSInput) {
			in.Settings.EnrollmentSettings.EnrollmentCA = enrollCA.ID
			in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsMTLS.ValidationCAs = []string{
				bootstrapCA.ID,
			}
			dmsModifier(in)
		})
		if err != nil {
			t.Fatalf("could not create DMS: %s", err)
		}

		bootKey, _ := helpers.GenerateECDSAKey(elliptic.P224())
		bootCsr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
		bootCrt, err := testServers.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
			CAID:         bootstrapCA.ID,
			CertRequest:  (*models.X509CertificateRequest)(bootCsr),
			SignVerbatim: true,
		})
		if err != nil {
			t.Fatalf("could not sign Bootstrap Certificate: %s", err)
		}

		estCli := est.Client{
			Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
			AdditionalPathSegment: dms.ID,
			Certificates:          []*x509.Certificate{(*x509.Certificate)(bootCrt.Certificate)},
			PrivateKey:            bootKey,
			InsecureSkipVerify:    true,
		}

		deviceID := fmt.Sprintf("enrolled-device-%s", uuid.NewString())
		enrollKey, _ := helpers.GenerateRSAKey(2048)
		enrollCSR, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

		enrollCRT, err := estCli.Enroll(context.Background(), enrollCSR)
		if err != nil {
			t.Fatalf("unexpected error while enrolling: %s", err)
		}

		return dms, (*x509.Certificate)(enrollCA.Certificate.Certificate), enrollCRT, enrollKey
	}

	checkReEnroll := func(tc *testing.T, caCert, cert *x509.Certificate, key any) {
		if err != nil {
			tc.Fatalf("unexpected error: %s", err)
		}

		priv, ok := key.(*rsa.PrivateKey)
		if !ok {
			tc.Fatalf("could not cast priv key into RSA")
		}

		valid, err := helpers.ValidateCertAndPrivKey(cert, priv, nil)
		if err != nil {
			tc.Fatalf("could not validate cert and key. Got error: %s", err)
		}

		if !valid {
			tc.Fatalf("private key does not match public key")
		}

		if err = helpers.ValidateCertificate(caCert, cert, true); err != nil {
			tc.Fatalf("could not validate certificate with CA: %s", err)
		}
	}

	var testcases = []struct {
		name        string
		run         func() (caCert *x509.Certificate, cert *x509.Certificate, key any, err error)
		resultCheck func(caCert *x509.Certificate, cert *x509.Certificate, key any, err error)
	}{
		{
			name: "OK",
			run: func() (caCert *x509.Certificate, cert *x509.Certificate, key any, err error) {
				dms, enrollmentCA, deviceCrt, deviceKey := prepReenrollScenario(
					func(in *services.CreateDMSInput) {
						in.Settings.ReEnrollmentSettings.ReEnrollmentDelta = models.TimeDuration(time.Hour)
					},
					"1m",
				)

				newCsr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: deviceCrt.Subject.CommonName}, deviceKey)

				estCli := est.Client{
					Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
					AdditionalPathSegment: dms.ID,
					Certificates:          []*x509.Certificate{deviceCrt},
					PrivateKey:            deviceKey,
					InsecureSkipVerify:    true,
				}

				reEnrollCRT, err := estCli.Reenroll(context.Background(), newCsr)
				if err != nil {
					t.Fatalf("unexpected error while enrolling: %s", err)
				}

				return enrollmentCA, reEnrollCRT, deviceKey, err
			},
			resultCheck: func(caCert, cert *x509.Certificate, key any, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}
				checkReEnroll(t, caCert, cert, key)
			},
		},
		{
			name: "Err/FakeCertificate",
			run: func() (caCert *x509.Certificate, cert *x509.Certificate, key any, err error) {
				dms, _, deviceCrt, deviceKey := prepReenrollScenario(
					func(in *services.CreateDMSInput) {
						in.Settings.ReEnrollmentSettings.ReEnrollmentDelta = models.TimeDuration(time.Hour)
					},
					"1m",
				)

				fakeKey, _ := helpers.GenerateRSAKey(2048)
				fakeCert, _ := helpers.GenerateSelfSignedCertificate(fakeKey, deviceCrt.Subject.CommonName)

				newCsr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: deviceCrt.Subject.CommonName}, deviceKey)

				estCli := est.Client{
					Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
					AdditionalPathSegment: dms.ID,
					Certificates:          []*x509.Certificate{fakeCert},
					PrivateKey:            fakeKey,
					InsecureSkipVerify:    true,
				}

				_, err = estCli.Reenroll(context.Background(), newCsr)
				return nil, nil, nil, err
			},
			resultCheck: func(caCert, cert *x509.Certificate, key any, err error) {
				if err == nil {
					t.Fatalf("expected error. Got none")
				}

				expectedErr := "invalid certificate"
				if !strings.Contains(err.Error(), expectedErr) {
					t.Fatalf("error should contain '%s'. Got error %s", expectedErr, err.Error())
				}
			},
		},
		{
			name: "Err/WindowNotOpened",
			run: func() (caCert *x509.Certificate, cert *x509.Certificate, key any, err error) {
				dms, _, deviceCrt, deviceKey := prepReenrollScenario(
					func(in *services.CreateDMSInput) {
						dur, _ := models.ParseDuration("3s")
						in.Settings.ReEnrollmentSettings.ReEnrollmentDelta = models.TimeDuration(dur)
					},
					"1m",
				)

				newCsr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: deviceCrt.Subject.CommonName}, deviceKey)

				estCli := est.Client{
					Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
					AdditionalPathSegment: dms.ID,
					Certificates:          []*x509.Certificate{deviceCrt},
					PrivateKey:            deviceKey,
					InsecureSkipVerify:    true,
				}

				_, err = estCli.Reenroll(context.Background(), newCsr)
				return nil, nil, nil, err
			},
			resultCheck: func(caCert, cert *x509.Certificate, key any, err error) {
				if err == nil {
					t.Fatalf("expected error. Got none")
				}

				expectedErr := "invalid reenroll window"
				if !strings.Contains(err.Error(), expectedErr) {
					t.Fatalf("error should contain '%s'. Got error %s", expectedErr, err.Error())
				}
			},
		},
		{
			name: "OK/AllowExpired",
			run: func() (caCert *x509.Certificate, cert *x509.Certificate, key any, err error) {
				dms, enrollmentCA, deviceCrt, deviceKey := prepReenrollScenario(
					func(in *services.CreateDMSInput) {
						in.Settings.ReEnrollmentSettings.ReEnrollmentDelta = models.TimeDuration(time.Hour)
						in.Settings.ReEnrollmentSettings.EnableExpiredRenewal = true
					},
					"2s",
				)

				newCsr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: deviceCrt.Subject.CommonName}, deviceKey)

				estCli := est.Client{
					Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
					AdditionalPathSegment: dms.ID,
					Certificates:          []*x509.Certificate{deviceCrt},
					PrivateKey:            deviceKey,
					InsecureSkipVerify:    true,
				}

				time.Sleep(time.Second * 4)

				reEnrollCRT, err := estCli.Reenroll(context.Background(), newCsr)
				if err != nil {
					t.Fatalf("unexpected error while enrolling: %s", err)
				}

				return enrollmentCA, reEnrollCRT, deviceKey, err
			},
			resultCheck: func(caCert, cert *x509.Certificate, key any, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}
				checkReEnroll(t, caCert, cert, key)
			},
		},
		{
			name: "Err/DenyExpired",
			run: func() (caCert *x509.Certificate, cert *x509.Certificate, key any, err error) {
				dms, _, deviceCrt, deviceKey := prepReenrollScenario(
					func(in *services.CreateDMSInput) {
						in.Settings.ReEnrollmentSettings.ReEnrollmentDelta = models.TimeDuration(time.Hour)
						in.Settings.ReEnrollmentSettings.EnableExpiredRenewal = false
					},
					"2s",
				)

				newCsr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: deviceCrt.Subject.CommonName}, deviceKey)

				estCli := est.Client{
					Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
					AdditionalPathSegment: dms.ID,
					Certificates:          []*x509.Certificate{deviceCrt},
					PrivateKey:            deviceKey,
					InsecureSkipVerify:    true,
				}

				time.Sleep(time.Second * 4)

				_, err = estCli.Reenroll(context.Background(), newCsr)
				return nil, nil, nil, err
			},
			resultCheck: func(caCert, cert *x509.Certificate, key any, err error) {
				if err == nil {
					t.Fatalf("expected error. Got none")
				}

				expectedErr := "expired certificate"
				if !strings.Contains(err.Error(), expectedErr) {
					t.Fatalf("error should contain '%s'. Got error %s", expectedErr, err.Error())
				}
			},
		},
		{
			name: "Err/DenyRevoked",
			run: func() (caCert *x509.Certificate, cert *x509.Certificate, key any, err error) {
				dms, _, deviceCrt, deviceKey := prepReenrollScenario(
					func(in *services.CreateDMSInput) {
						in.Settings.ReEnrollmentSettings.ReEnrollmentDelta = models.TimeDuration(time.Hour)
						in.Settings.ReEnrollmentSettings.EnableExpiredRenewal = false
					},
					"2s",
				)

				newCsr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: deviceCrt.Subject.CommonName}, deviceKey)

				estCli := est.Client{
					Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
					AdditionalPathSegment: dms.ID,
					Certificates:          []*x509.Certificate{deviceCrt},
					PrivateKey:            deviceKey,
					InsecureSkipVerify:    true,
				}

				_, err = testServers.CA.Service.UpdateCertificateStatus(context.Background(), services.UpdateCertificateStatusInput{
					SerialNumber:     helpers.SerialNumberToString(deviceCrt.SerialNumber),
					NewStatus:        models.StatusRevoked,
					RevocationReason: ocsp.Superseded,
				})
				if err != nil {
					t.Fatalf("could not revoke certificate: %s", err)
				}

				_, err = estCli.Reenroll(context.Background(), newCsr)
				return nil, nil, nil, err
			},
			resultCheck: func(caCert, cert *x509.Certificate, key any, err error) {
				if err == nil {
					t.Fatalf("expected error. Got none")
				}

				expectedErr := "certificate is revoked"
				if !strings.Contains(err.Error(), expectedErr) {
					t.Fatalf("error should contain '%s'. Got error %s", expectedErr, err.Error())
				}
			},
		},
		{
			name: "OK/RotateCAWithAdditionalValCAs",
			run: func() (caCert *x509.Certificate, cert *x509.Certificate, key any, err error) {
				dms, _, deviceCrt, deviceKey := prepReenrollScenario(
					func(in *services.CreateDMSInput) {
						in.Settings.ReEnrollmentSettings.ReEnrollmentDelta = models.TimeDuration(time.Hour)
						in.Settings.ReEnrollmentSettings.EnableExpiredRenewal = false
					},
					"5m",
				)

				newCA, err := createCA(fmt.Sprintf("rotated-ca-%s", uuid.NewString()), "5y", "1y")
				if err != nil {
					t.Fatalf("could not create Rotational CA: %s", err)
				}

				dms.Settings.ReEnrollmentSettings.AdditionalValidationCAs = append(dms.Settings.ReEnrollmentSettings.AdditionalValidationCAs, dms.Settings.EnrollmentSettings.EnrollmentCA)
				dms.Settings.EnrollmentSettings.EnrollmentCA = newCA.ID
				dms, err = dmsMgr.HttpDeviceManagerSDK.UpdateDMS(context.Background(), services.UpdateDMSInput{
					DMS: *dms,
				})
				if err != nil {
					t.Fatalf("could not create update DMS: %s", err)
				}

				newCsr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: deviceCrt.Subject.CommonName}, deviceKey)

				estCli := est.Client{
					Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
					AdditionalPathSegment: dms.ID,
					Certificates:          []*x509.Certificate{deviceCrt},
					PrivateKey:            deviceKey,
					InsecureSkipVerify:    true,
				}

				reEnrollCRT, err := estCli.Reenroll(context.Background(), newCsr)
				if err != nil {
					t.Fatalf("unexpected error while enrolling: %s", err)
				}

				return (*x509.Certificate)(newCA.Certificate.Certificate), reEnrollCRT, deviceKey, err
			},
			resultCheck: func(caCert, cert *x509.Certificate, key any, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}
				checkReEnroll(t, caCert, cert, key)
			},
		},
		{
			name: "Err/SubjectModified",
			run: func() (caCert *x509.Certificate, cert *x509.Certificate, key any, err error) {
				dms, _, deviceCrt, deviceKey := prepReenrollScenario(
					func(in *services.CreateDMSInput) {
						in.Settings.ReEnrollmentSettings.ReEnrollmentDelta = models.TimeDuration(time.Hour)
					},
					"1m",
				)

				newCsr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: deviceCrt.Subject.CommonName, Organization: "MyOrg"}, deviceKey)

				estCli := est.Client{
					Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
					AdditionalPathSegment: dms.ID,
					Certificates:          []*x509.Certificate{deviceCrt},
					PrivateKey:            deviceKey,
					InsecureSkipVerify:    true,
				}

				_, err = estCli.Reenroll(context.Background(), newCsr)
				return nil, nil, nil, err
			},
			resultCheck: func(caCert, cert *x509.Certificate, key any, err error) {
				if err == nil {
					t.Fatalf("expected error. Got none")
				}

				expectedErr := "invalid RawSubject bytes"
				if !strings.Contains(err.Error(), expectedErr) {
					t.Fatalf("error should contain '%s'. Got error %s", expectedErr, err.Error())
				}
			},
		},
		{
			name: "OK/PEMOutput",
			run: func() (caCert *x509.Certificate, cert *x509.Certificate, key any, err error) {
				dms, enrollmentCA, deviceCrt, deviceKey := prepReenrollScenario(
					func(in *services.CreateDMSInput) {
						in.Settings.ReEnrollmentSettings.ReEnrollmentDelta = models.TimeDuration(time.Hour)
					},
					"1m",
				)

				newCsr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: deviceCrt.Subject.CommonName}, deviceKey)

				estCli := pemESTClient{
					baseEndpoint: fmt.Sprintf("https://localhost:%d/.well-known/est/%s", dmsMgr.Port, dms.ID),
					cert:         deviceCrt,
					key:          deviceKey,
				}

				reEnrollCRT, err := estCli.ReEnroll(newCsr)
				if err != nil {
					t.Fatalf("unexpected error while enrolling: %s", err)
				}

				return enrollmentCA, reEnrollCRT, deviceKey, err
			},
			resultCheck: func(caCert, cert *x509.Certificate, key any, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}
				checkReEnroll(t, caCert, cert, key)
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			tc.resultCheck(tc.run())
		})
	}
}

func checkDMS(t *testing.T, dms *models.DMS, dmsSample services.CreateDMSInput) {
	if dms.ID != dmsSample.ID {
		t.Fatalf("device id mismatch: expected %s, got %s", dmsSample.ID, dms.ID)
	}
}

type pemESTClient struct {
	cert         *x509.Certificate
	key          any
	baseEndpoint string
}

func (c *pemESTClient) Enroll(r *x509.CertificateRequest) (*x509.Certificate, error) {
	return c.commonEnrollPEM(r, false)
}
func (c *pemESTClient) ReEnroll(r *x509.CertificateRequest) (*x509.Certificate, error) {
	return c.commonEnrollPEM(r, true)
}

func (c *pemESTClient) commonEnrollPEM(r *x509.CertificateRequest, renew bool) (*x509.Certificate, error) {
	keyPem, err := helpers.PrivateKeyToPEM(c.key)
	if err != nil {
		return nil, err
	}

	cer, err := tls.X509KeyPair([]byte(helpers.CertificateToPEM(c.cert)), []byte(keyPem))
	if err != nil {
		return nil, err
	}

	client := http.Client{}
	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{cer},
		},
	}

	reqBody := io.NopCloser(bytes.NewBuffer([]byte(base64.StdEncoding.EncodeToString(r.Raw))))

	var endpoint = "/simpleenroll"
	if renew {
		endpoint = "/simplereenroll"
	}

	uriEndpoint := fmt.Sprintf("%s%s", c.baseEndpoint, endpoint)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, uriEndpoint, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to make new HTTP request: %w", err)
	}

	req.Header.Set("User-Agent", "pem-test")
	req.Header.Set("Accept", "application/x-pem-file")
	req.Header.Set("Content-Type", "application/pkcs10")
	req.Header.Set("Content-Transfer-Encoding", "base64")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute HTTP request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("non 200 status code: %s", resp.Status)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	cert, err := helpers.ParseCertificate(string(b))
	if err != nil {
		return nil, err
	}

	return cert, nil
}
