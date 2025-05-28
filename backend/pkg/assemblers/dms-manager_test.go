package assemblers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/globalsign/est"
	"github.com/google/uuid"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	identityextractors "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/identity-extractors"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ocsp"
)

func StartDMSManagerServiceTestServer(t *testing.T, withEventBus bool) (*DMSManagerTestServer, *TestServer, error) {
	builder := TestServiceBuilder{}.WithDatabase("ca", "devicemanager", "dmsmanager").WithService(CA, DEVICE_MANAGER, DMS_MANAGER)
	if withEventBus {
		builder = builder.WithEventBus()
	}

	testServer, err := builder.Build(t)
	if err != nil {
		return nil, nil, err
	}

	err = testServer.BeforeEach()
	if err != nil {
		t.Fatalf("could not run 'BeforeEach' cleanup func in test case: %s", err)
	}

	return testServer.DMSManager, testServer, nil
}

const dmsID = "1234-5678"

func TestCreateDMS(t *testing.T) {
	dmsMgr, _, err := StartDMSManagerServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create DMS Manager test server: %s", err)
	}

	dmsSample := services.CreateDMSInput{
		ID:   dmsID,
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

	dmsFromDB, err := dmsMgr.Service.GetDMSByID(context.Background(), services.GetDMSByIDInput{ID: dmsSample.ID})
	if err != nil {
		t.Fatalf("could not get DMS by ID: %s", err)
	}
	checkDMS(t, dmsFromDB, dmsSample)
}

func TestUpdateDMS(t *testing.T) {
	dmsMgr, _, err := StartDMSManagerServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create DMS Manager test server: %s", err)
	}

	dmsSample := services.CreateDMSInput{
		ID:   dmsID,
		Name: "MyIotFleet",
	}
	dms, err := dmsMgr.HttpDeviceManagerSDK.CreateDMS(context.Background(), dmsSample)
	if err != nil {
		t.Fatalf("could not create DMS: %s", err)
	}
	assert.Equal(t, dms.Name, dmsSample.Name)

	dms.Name = "MyIotFleet2"

	_, err = dmsMgr.Service.UpdateDMS(context.Background(), services.UpdateDMSInput{DMS: *dms})
	if err != nil {
		t.Fatalf("could not update DMS: %s", err)
	}

	dmsFromDB, err := dmsMgr.Service.GetDMSByID(context.Background(), services.GetDMSByIDInput{ID: dmsSample.ID})
	if err != nil {
		t.Fatalf("could not get DMS by ID: %s", err)
	}

	assert.Equal(t, dms.Name, dmsFromDB.Name)
}

func TestDeleteDMS(t *testing.T) {

	testcases := []struct {
		name        string
		setup       func(dmsMgr *DMSManagerTestServer)
		resultCheck func(dmsMgr *DMSManagerTestServer, err error)
	}{
		{
			name: "OK",
			setup: func(dmsMgr *DMSManagerTestServer) {
				dmsSample := services.CreateDMSInput{
					ID:   dmsID,
					Name: "MyIotFleet",
				}
				dms, err := dmsMgr.HttpDeviceManagerSDK.CreateDMS(context.Background(), dmsSample)
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}
				assert.Equal(t, dms.Name, dmsSample.Name)
			},
			resultCheck: func(dmsMgr *DMSManagerTestServer, err error) {
				if err != nil {
					t.Fatalf("could not delete DMS: %s", err)
				}

				_, err = dmsMgr.Service.GetDMSByID(context.Background(), services.GetDMSByIDInput{ID: dmsID})
				if err == nil {
					t.Fatalf("Get DMS by ID should fail")
				}

				assert.ErrorIs(t, err, errs.ErrDMSNotFound)
			},
		},
		{
			name:  "Error - DMS not found",
			setup: func(dmsMgr *DMSManagerTestServer) {},
			resultCheck: func(dmsMgr *DMSManagerTestServer, err error) {
				if err == nil {
					t.Fatalf("Delete DMS should fail")
				}

				assert.ErrorIs(t, err, errs.ErrDMSNotFound)
			},
		},
	}
	for _, tc := range testcases {

		t.Run(tc.name, func(t *testing.T) {

			dmsMgr, _, err := StartDMSManagerServiceTestServer(t, false)
			if err != nil {
				t.Fatalf("could not create DMS Manager test server: %s", err)
			}

			tc.setup(dmsMgr)

			err = dmsMgr.Service.DeleteDMS(context.Background(), services.DeleteDMSInput{ID: dmsID})

			tc.resultCheck(dmsMgr, err)
		})
	}
}

func TestUpdateMissingDMSShouldFail(t *testing.T) {
	dmsMgr, _, err := StartDMSManagerServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create DMS Manager test server: %s", err)
	}

	dmsSample := models.DMS{
		ID:   dmsID,
		Name: "MyIotFleet",
	}

	_, err = dmsMgr.Service.UpdateDMS(context.Background(), services.UpdateDMSInput{DMS: dmsSample})
	if err == nil {
		t.Fatalf("Update DMS should fail")
	}

	assert.ErrorIs(t, err, errs.ErrDMSNotFound)
}

func TestGetMissingDMSShouldFail(t *testing.T) {
	dmsMgr, _, err := StartDMSManagerServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create DMS Manager test server: %s", err)
	}

	_, err = dmsMgr.Service.GetDMSByID(context.Background(), services.GetDMSByIDInput{ID: dmsID})
	if err == nil {
		t.Fatalf("Get DMS by ID should fail")
	}

	assert.ErrorIs(t, err, errs.ErrDMSNotFound)
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
		return testServers.CA.Service.CreateCA(ctx, services.CreateCAInput{
			KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 224},
			Subject:            models.Subject{CommonName: name},
			CAExpiration:       models.Validity{Type: models.Duration, Duration: (models.TimeDuration)(lifespanCABootDur)},
			IssuanceExpiration: models.Validity{Type: models.Duration, Duration: (models.TimeDuration)(issuanceCABootDur)},
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

				bootKey, _ := chelpers.GenerateECDSAKey(elliptic.P224())
				bootCsr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
				bootCrt, err := testServers.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:        bootstrapCA.ID,
					CertRequest: (*models.X509CertificateRequest)(bootCsr),
					IssuanceProfile: models.IssuanceProfile{
						Validity:        bootstrapCA.Validity,
						SignAsCA:        false,
						HonorSubject:    true,
						HonorExtensions: true,
					},
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
				enrollKey, _ := chelpers.GenerateECDSAKey(elliptic.P224())
				enrollCSR, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

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

				valid, err := chelpers.ValidateCertAndPrivKey(cert, nil, priv)
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

				bootKey, _ := chelpers.GenerateECDSAKey(elliptic.P224())
				bootCsr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
				bootCrt, err := testServers.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:        bootstrapCA.ID,
					CertRequest: (*models.X509CertificateRequest)(bootCsr),
					IssuanceProfile: models.IssuanceProfile{
						Validity:        bootstrapCA.Validity,
						SignAsCA:        false,
						HonorSubject:    true,
						HonorExtensions: true,
					},
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
				enrollKey, _ := chelpers.GenerateRSAKey(2048)
				enrollCSR, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

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

				valid, err := chelpers.ValidateCertAndPrivKey(cert, priv, nil)
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

				bootKey, _ := chelpers.GenerateECDSAKey(elliptic.P224())
				bootCsr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
				bootCrt, err := testServers.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:        bootstrapCA.ID,
					CertRequest: (*models.X509CertificateRequest)(bootCsr),
					IssuanceProfile: models.IssuanceProfile{
						Validity:        bootstrapCA.Validity,
						SignAsCA:        false,
						HonorSubject:    true,
						HonorExtensions: true,
					},
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
				enrollKey, _ := chelpers.GenerateRSAKey(2048)
				enrollCSR, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

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

				valid, err := chelpers.ValidateCertAndPrivKey(cert, priv, nil)
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
			name: "OK/ManualRegistration",
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
					in.Settings.EnrollmentSettings.RegistrationMode = models.JITP // It is not MANDATORY to register the device before enrolling. Test that it works if manual registration is performed
					in.Settings.EnrollmentSettings.EnrollmentCA = enrollCA.ID
					in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsMTLS.ValidationCAs = []string{
						bootstrapCA.ID,
					}
				})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}

				bootKey, _ := chelpers.GenerateECDSAKey(elliptic.P224())
				bootCsr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
				bootCrt, err := testServers.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:        bootstrapCA.ID,
					CertRequest: (*models.X509CertificateRequest)(bootCsr),
					IssuanceProfile: models.IssuanceProfile{
						Validity:        bootstrapCA.Validity,
						SignAsCA:        false,
						HonorSubject:    true,
						HonorExtensions: true,
					},
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
				enrollKey, _ := chelpers.GenerateRSAKey(2048)
				enrollCSR, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

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

				valid, err := chelpers.ValidateCertAndPrivKey(cert, priv, nil)
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

				bootKey, _ := chelpers.GenerateECDSAKey(elliptic.P224())
				bootCsr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
				bootCrt, err := testServers.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:        bootstrapCA.ID,
					CertRequest: (*models.X509CertificateRequest)(bootCsr),
					IssuanceProfile: models.IssuanceProfile{
						Validity:        bootstrapCA.Validity,
						SignAsCA:        false,
						HonorSubject:    true,
						HonorExtensions: true,
					},
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
				enrollKey, _ := chelpers.GenerateRSAKey(2048)
				enrollCSR, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

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

				fakeKey, _ := chelpers.GenerateRSAKey(2048)
				fakeCert, _ := chelpers.GenerateSelfSignedCertificate(fakeKey, "my-fake-cert")
				estCli := est.Client{
					Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
					AdditionalPathSegment: dms.ID,
					Certificates:          []*x509.Certificate{fakeCert},
					PrivateKey:            fakeKey,
					InsecureSkipVerify:    true,
				}

				deviceID := fmt.Sprintf("enrolled-device-%s", uuid.NewString())
				enrollKey, _ := chelpers.GenerateRSAKey(2048)
				enrollCSR, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

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
			name: "Err/ExpiredCertificateNotAllowed",
			run: func() (caCert, cert *x509.Certificate, key any, err error) {
				bootstrapCA, err := createCA("boot", "1y", "1s")
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

				bootKey, _ := chelpers.GenerateECDSAKey(elliptic.P224())
				bootCsr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
				bootCrt, err := testServers.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:        bootstrapCA.ID,
					CertRequest: (*models.X509CertificateRequest)(bootCsr),
					IssuanceProfile: models.IssuanceProfile{
						Validity:        bootstrapCA.Validity,
						SignAsCA:        false,
						HonorSubject:    true,
						HonorExtensions: true,
					},
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
				enrollKey, _ := chelpers.GenerateRSAKey(2048)
				enrollCSR, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

				// Wait for the certificate to expire
				time.Sleep(2 * time.Second)

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
			name: "Ok/ExpiredCertificateAllowed",
			run: func() (caCert, cert *x509.Certificate, key any, err error) {
				bootstrapCA, err := createCA("boot", "1y", "1s")
				if err != nil {
					t.Fatalf("could not create bootstrap CA: %s", err)
				}

				enrollCA, err := createCA("enroll", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create Enrollment CA: %s", err)
				}

				dms, err := createDMS(func(in *services.CreateDMSInput) {
					in.Settings.EnrollmentSettings.EnrollmentCA = enrollCA.ID
					in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsMTLS.AllowExpired = true
					in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsMTLS.ValidationCAs = []string{
						bootstrapCA.ID,
					}
				})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}

				bootKey, _ := chelpers.GenerateECDSAKey(elliptic.P224())
				bootCsr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
				bootCrt, err := testServers.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:        bootstrapCA.ID,
					CertRequest: (*models.X509CertificateRequest)(bootCsr),
					IssuanceProfile: models.IssuanceProfile{
						Validity:        bootstrapCA.Validity,
						SignAsCA:        false,
						HonorSubject:    true,
						HonorExtensions: true,
					},
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
				enrollKey, _ := chelpers.GenerateRSAKey(2048)
				enrollCSR, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

				// Wait for the certificate to expire
				time.Sleep(2 * time.Second)

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

				priv, ok := key.(*rsa.PrivateKey)
				if !ok {
					t.Fatalf("could not cast priv key into RSA")
				}

				valid, err := chelpers.ValidateCertAndPrivKey(cert, priv, nil)
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

				bootKey, _ := chelpers.GenerateECDSAKey(elliptic.P224())
				bootCsr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
				bootCrt, err := testServers.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:        bootstrapCA.ID,
					CertRequest: (*models.X509CertificateRequest)(bootCsr),
					IssuanceProfile: models.IssuanceProfile{
						Validity:        bootstrapCA.Validity,
						SignAsCA:        false,
						HonorSubject:    true,
						HonorExtensions: true,
					},
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
				enrollKey, _ := chelpers.GenerateRSAKey(2048)
				enrollCSR, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

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
		{
			name: "Err/RevokedCertificateExpiredAllowed",
			run: func() (caCert, cert *x509.Certificate, key any, err error) {
				bootstrapCA, err := createCA("boot", "1y", "1s")
				if err != nil {
					t.Fatalf("could not create bootstrap CA: %s", err)
				}

				enrollCA, err := createCA("enroll", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create Enrollment CA: %s", err)
				}

				dms, err := createDMS(func(in *services.CreateDMSInput) {
					in.Settings.EnrollmentSettings.EnrollmentCA = enrollCA.ID
					in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsMTLS.AllowExpired = true
					in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsMTLS.ValidationCAs = []string{
						bootstrapCA.ID,
					}
				})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}

				bootKey, _ := chelpers.GenerateECDSAKey(elliptic.P224())
				bootCsr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
				bootCrt, err := testServers.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:        bootstrapCA.ID,
					CertRequest: (*models.X509CertificateRequest)(bootCsr),
					IssuanceProfile: models.IssuanceProfile{
						Validity:        bootstrapCA.Validity,
						SignAsCA:        false,
						HonorSubject:    true,
						HonorExtensions: true,
					},
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
				enrollKey, _ := chelpers.GenerateRSAKey(2048)
				enrollCSR, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

				// Wait for the certificate to expire
				time.Sleep(2 * time.Second)

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
		{
			name: "Err/AlreadyEnrolled",
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
					in.Settings.EnrollmentSettings.EnableReplaceableEnrollment = false
					in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsMTLS.ValidationCAs = []string{
						bootstrapCA.ID,
					}
				})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}

				bootKey, _ := chelpers.GenerateECDSAKey(elliptic.P224())
				bootCsr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
				bootCrt, err := testServers.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:        bootstrapCA.ID,
					CertRequest: (*models.X509CertificateRequest)(bootCsr),
					IssuanceProfile: models.IssuanceProfile{
						Validity:        bootstrapCA.Validity,
						SignAsCA:        false,
						HonorSubject:    true,
						HonorExtensions: true,
					},
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
				enrollKey, _ := chelpers.GenerateRSAKey(2048)
				enrollCSR, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

				_, err = estCli.Enroll(context.Background(), enrollCSR)
				if err != nil {
					t.Fatalf("could not enroll device for the first time: %s", err)
				}

				_, err = estCli.Enroll(context.Background(), enrollCSR)
				return nil, nil, nil, err
			},
			resultCheck: func(caCert, cert *x509.Certificate, key any, err error) {
				if err == nil {
					t.Fatalf("expected error. Got none")
				}

				expectedErr := "forbiddenNewEnrollment"
				if !strings.Contains(err.Error(), expectedErr) {
					t.Fatalf("error should contain '%s'. Got error %s", expectedErr, err.Error())
				}
			},
		},
		{
			name: "Err/BelongsToOtherDMS",
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
					in.Settings.EnrollmentSettings.EnableReplaceableEnrollment = true
					in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsMTLS.ValidationCAs = []string{
						bootstrapCA.ID,
					}
				})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}

				dms2, err := createDMS(func(in *services.CreateDMSInput) {
					in.Settings.EnrollmentSettings.EnrollmentCA = enrollCA.ID
					in.Settings.EnrollmentSettings.EnableReplaceableEnrollment = true
					in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsMTLS.ValidationCAs = []string{
						bootstrapCA.ID,
					}
				})
				if err != nil {
					t.Fatalf("could not create DMS 2: %s", err)
				}

				bootKey, _ := chelpers.GenerateECDSAKey(elliptic.P224())
				bootCsr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
				bootCrt, err := testServers.CA.Service.SignCertificate(ctx, services.SignCertificateInput{
					CAID:        bootstrapCA.ID,
					CertRequest: (*models.X509CertificateRequest)(bootCsr),
					IssuanceProfile: models.IssuanceProfile{
						Validity:        bootstrapCA.Validity,
						SignAsCA:        false,
						HonorSubject:    true,
						HonorExtensions: true,
					},
				})
				if err != nil {
					t.Fatalf("could not sign Bootstrap Certificate: %s", err)
				}

				estCli := est.Client{
					Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
					AdditionalPathSegment: dms2.ID, // This is the key part. We will be enrolling in DMS2
					Certificates:          []*x509.Certificate{(*x509.Certificate)(bootCrt.Certificate)},
					PrivateKey:            bootKey,
					InsecureSkipVerify:    true,
				}

				deviceID := fmt.Sprintf("enrolled-device-%s", uuid.NewString())

				_, err = testServers.DeviceManager.Service.CreateDevice(ctx, services.CreateDeviceInput{
					ID:        deviceID,
					Alias:     deviceID,
					Tags:      []string{},
					Metadata:  map[string]any{},
					DMSID:     dms.ID, // But the device belongs to DMS1
					Icon:      "test2",
					IconColor: "#000001",
				})
				if err != nil {
					t.Fatalf("could not register device: %s", err)
				}

				enrollKey, _ := chelpers.GenerateRSAKey(2048)
				enrollCSR, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

				_, err = estCli.Enroll(context.Background(), enrollCSR)
				return nil, nil, nil, err
			},
			resultCheck: func(caCert, cert *x509.Certificate, key any, err error) {
				if err == nil {
					t.Fatalf("expected error. Got none")
				}

				expectedErr := "device already registered to another DMS"
				if !strings.Contains(err.Error(), expectedErr) {
					t.Fatalf("error should contain '%s'. Got error %s", expectedErr, err.Error())
				}
			},
		},
		{
			name: "OK/ExternalWebHook",
			run: func() (caCert, cert *x509.Certificate, key any, err error) {
				enrollCA, err := createCA("enroll", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create Enrollment CA: %s", err)
				}

				router, url, cleanup, err := startWebhookServer()
				if err != nil {
					t.Fatalf("could not start webhook server: %s", err)
				}

				defer cleanup()

				router.POST("/verify", func(c *gin.Context) {
					var b map[string]interface{}
					err := c.BindJSON(&b)
					if err != nil {
						c.JSON(400, gin.H{})
						return
					}

					if b["csr"] == nil || b["csr"].(string) == "" {
						c.JSON(400, gin.H{})
						return
					}
					if b["aps"] == nil || b["aps"].(string) == "" {
						c.JSON(400, gin.H{})
						return
					}
					if b["device_cn"] == nil || b["device_cn"].(string) == "" {
						c.JSON(400, gin.H{})
						return
					}
					if b["http_request"] == nil {
						c.JSON(400, gin.H{})
						return
					}

					request := b["http_request"].(map[string]interface{})
					if request["headers"] == nil || request["headers"].(map[string]interface{}) == nil {
						c.JSON(400, gin.H{})
						return
					}
					if request["url"] == nil || request["url"].(string) == "" {
						c.JSON(400, gin.H{})
						return
					}

					c.JSON(200, gin.H{"authorized": true})
				})

				dms, err := createDMS(func(in *services.CreateDMSInput) {
					in.Settings.EnrollmentSettings.EnrollmentCA = enrollCA.ID
					in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthMode = "EXTERNAL_WEBHOOK"
					in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsExternalWebhook = models.WebhookCall{
						Name: "myHook",
						Url:  url + "/verify",
						Config: models.WebhookCallHttpClient{
							ValidateServerCert: false,
							LogLevel:           string(config.Debug),
							AuthMode:           config.NoAuth,
						},
					}
				})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}

				estCli := est.Client{
					Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
					AdditionalPathSegment: dms.ID,
					Certificates:          []*x509.Certificate{},
					PrivateKey:            nil,
					InsecureSkipVerify:    true,
				}

				deviceID := fmt.Sprintf("enrolled-device-%s", uuid.NewString())
				enrollKey, _ := chelpers.GenerateRSAKey(2048)
				enrollCSR, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

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
			},
		},
		{
			name: "Err/ExternalWebHookUnauthorized",
			run: func() (caCert, cert *x509.Certificate, key any, err error) {
				enrollCA, err := createCA("enroll", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create Enrollment CA: %s", err)
				}

				router, url, cleanup, err := startWebhookServer()
				if err != nil {
					t.Fatalf("could not start webhook server: %s", err)
				}

				defer cleanup()

				router.POST("/verify", func(c *gin.Context) {
					c.JSON(200, gin.H{"authorized": false})
				})

				dms, err := createDMS(func(in *services.CreateDMSInput) {
					in.Settings.EnrollmentSettings.EnrollmentCA = enrollCA.ID
					in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthMode = "EXTERNAL_WEBHOOK"
					in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsExternalWebhook = models.WebhookCall{
						Name: "myHook",
						Url:  url + "/verify",
						Config: models.WebhookCallHttpClient{
							ValidateServerCert: false,
							LogLevel:           string(config.Debug),
							AuthMode:           config.NoAuth,
						},
					}
				})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}

				estCli := est.Client{
					Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
					AdditionalPathSegment: dms.ID,
					Certificates:          []*x509.Certificate{},
					PrivateKey:            nil,
					InsecureSkipVerify:    true,
				}

				deviceID := fmt.Sprintf("enrolled-device-%s", uuid.NewString())
				enrollKey, _ := chelpers.GenerateRSAKey(2048)
				enrollCSR, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

				_, err = estCli.Enroll(context.Background(), enrollCSR)
				return nil, nil, nil, err
			},
			resultCheck: func(caCert *x509.Certificate, cert *x509.Certificate, key any, err error) {
				if err == nil {
					t.Fatalf("expected error. Got none")
				}

				if !strings.Contains(err.Error(), "external webhook denied enrollment") {
					t.Fatalf("error should contain 'external webhook denied enrollment'. Got error %s", err.Error())
				}
			},
		},
		{
			name: "OK/ExternalWebHook-WithApiKey",
			run: func() (caCert, cert *x509.Certificate, key any, err error) {
				enrollCA, err := createCA("enroll", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create Enrollment CA: %s", err)
				}

				router, url, cleanup, err := startWebhookServer()
				if err != nil {
					t.Fatalf("could not start webhook server: %s", err)
				}

				defer cleanup()

				router.POST("/verify", func(c *gin.Context) {
					apiKey := c.GetHeader("X-API-Key")
					if apiKey != "mySecret" {
						c.JSON(401, gin.H{})
						return
					}

					c.JSON(200, gin.H{"authorized": true})
				})

				dms, err := createDMS(func(in *services.CreateDMSInput) {
					in.Settings.EnrollmentSettings.EnrollmentCA = enrollCA.ID
					in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthMode = "EXTERNAL_WEBHOOK"
					in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsExternalWebhook = models.WebhookCall{
						Name: "myHook",
						Url:  url + "/verify",
						Config: models.WebhookCallHttpClient{
							ValidateServerCert: false,
							LogLevel:           string(config.Debug),
							AuthMode:           config.NoAuth,
						},
					}
				})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}

				estCli := est.Client{
					Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
					AdditionalPathSegment: dms.ID,
					Certificates:          []*x509.Certificate{},
					PrivateKey:            nil,
					InsecureSkipVerify:    true,
				}

				deviceID := fmt.Sprintf("enrolled-device-%s", uuid.NewString())
				enrollKey, _ := chelpers.GenerateRSAKey(2048)
				enrollCSR, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

				_, err = estCli.Enroll(context.Background(), enrollCSR)
				if err == nil {
					t.Fatalf("expected error. Got none")
				}
				if !strings.Contains(err.Error(), "status code: 401") {
					t.Fatalf("error should contain 'status code: 401'. Got error %s", err.Error())
				}

				dms.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsExternalWebhook.Config.AuthMode = config.ApiKey
				dms.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsExternalWebhook.Config.ApiKey = models.WebhookCallHttpClientApiKey{
					Header: "X-API-Key",
					Key:    "mySecret",
				}

				_, err = dmsMgr.Service.UpdateDMS(context.Background(), services.UpdateDMSInput{
					DMS: *dms,
				})
				if err != nil {
					t.Fatalf("could not update DMS: %s", err)
				}

				enrollCRT, err := estCli.Enroll(context.Background(), enrollCSR)
				return (*x509.Certificate)(enrollCA.Certificate.Certificate), enrollCRT, enrollKey, err
			},
			resultCheck: func(caCert *x509.Certificate, cert *x509.Certificate, key any, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
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
		// 			CAExpiration:       models.Validity{Type: models.Duration, Duration: (*models.TimeDuration)(&lifespanCABootDur)},
		// 			IssuanceExpiration: models.Validity{Type: models.Duration, Duration: (*models.TimeDuration)(&issuanceCABootDur)},
		// 			Metadata:           map[string]any{},
		// 		})
		// 		if err != nil {
		// 			t.Fatalf("could not create external Bootstrap CA: %s", err)
		// 		}

		// 		importedBootstrapCA, err := testServers.CA.Service.ImportCA(context.Background(), services.ImportCAInput{
		// 			ID:                 fmt.Sprintf("my-external-CA-%s", uuid.NewString()),
		// 			CAType:             models.CertificateTypeExternal,
		// 			IssuanceExpiration: models.Validity{Type: models.Duration, Duration: (*models.TimeDuration)(&issuanceCABootDur)},
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

		// 		bootKey, _ := chelpers.GenerateECDSAKey(elliptic.P224())
		// 		bootCsr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
		// 		bootCrt, err := externalTestServers.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
		// 			CAID:         bootstrapCA.ID,
		// 			CertRequest:  (*models.X509CertificateRequest)(bootCsr),
		// 			IssuanceProfile: models.IssuanceProfile{
		// 				Validity:        bootstrapCA.Validity,
		// 					SignAsCA:        false,
		// 					HonorSubject:    true,
		// 					HonorExtensions: true,
		// 			},
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
		// 		enrollKey, _ := chelpers.GenerateRSAKey(2048)
		// 		enrollCSR, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

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

				bootKey, _ := chelpers.GenerateECDSAKey(elliptic.P224())
				bootCsr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
				bootCrt, err := testServers.CA.Service.SignCertificate(ctx, services.SignCertificateInput{
					CAID:        bootstrapCA.ID,
					CertRequest: (*models.X509CertificateRequest)(bootCsr),
					IssuanceProfile: models.IssuanceProfile{
						Validity:        bootstrapCA.Validity,
						SignAsCA:        false,
						HonorSubject:    true,
						HonorExtensions: true,
					},
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
				enrollKey, _ := chelpers.GenerateRSAKey(2048)
				enrollCSR, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

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

				valid, err := chelpers.ValidateCertAndPrivKey(cert, priv, nil)
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

func TestESTGetCACerts(t *testing.T) {
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
			CAExpiration:       models.Validity{Type: models.Duration, Duration: (models.TimeDuration)(lifespanCABootDur)},
			IssuanceExpiration: models.Validity{Type: models.Duration, Duration: (models.TimeDuration)(issuanceCABootDur)},
			Metadata:           map[string]any{},
		})
	}
	enrollCA, err := createCA("enroll", "1y", "4w")
	if err != nil {
		t.Fatalf("could not create the enrollment CA: %s", err)
	}
	caMm, err := createCA("managedCA", "10m", "5m")

	if err != nil {
		t.Fatalf("unexpected error while creating the CA: %s", err)
	}

	createDMS := func(modifier func(in *services.CreateDMSInput)) (*models.DMS, error) {
		input := services.CreateDMSInput{
			ID:       uuid.NewString(),
			Name:     "MyIotFleet",
			Metadata: map[string]any{},
			Settings: models.DMSSettings{
				EnrollmentSettings: models.EnrollmentSettings{
					EnrollmentProtocol: models.EST,
					EnrollmentCA:       "",
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

	createDMS(func(in *services.CreateDMSInput) {
		// Create DMS without modifications on the base config
	})
	var testcases = []struct {
		name        string
		run         func() (caCerts []*x509.Certificate, err error)
		resultCheck func(caCerts []*x509.Certificate, err error)
	}{
		{
			name: "Err/DmsNotExist",
			run: func() (caCert []*x509.Certificate, err error) {

				estCli := est.Client{
					Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
					AdditionalPathSegment: "test",
					InsecureSkipVerify:    true,
				}

				_, err = estCli.CACerts(context.Background())

				return nil, err
			},
			resultCheck: func(caCerts []*x509.Certificate, err error) {
				if err == nil {
					t.Fatalf("should've got error but got none")
				}
			},
		},
		{
			name: "OK/IncludeLamassuSystemCA",
			run: func() (caCert []*x509.Certificate, err error) {

				dms, err := createDMS(func(in *services.CreateDMSInput) {
					in.Settings.CADistributionSettings.IncludeEnrollmentCA = false
					in.Settings.CADistributionSettings.IncludeLamassuSystemCA = true
				})
				if err != nil {
					t.Fatalf("unexpected error while creating the DMS: %s", err)
				}

				estCli := est.Client{
					Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
					AdditionalPathSegment: dms.ID,
					InsecureSkipVerify:    true,
				}

				caCerts, err := estCli.CACerts(context.Background())

				return caCerts, err
			},
			resultCheck: func(caCerts []*x509.Certificate, err error) {
				if err != nil {
					t.Fatalf("should've not got error but got an error")
				}
				if len(caCerts) != 1 {
					t.Fatalf("should've got only one cacert")
				}
			},
		},
		{
			name: "OK/IncludeEnrollmentCA",
			run: func() (caCert []*x509.Certificate, err error) {
				dms, err := createDMS(func(in *services.CreateDMSInput) {
					in.Settings.CADistributionSettings.IncludeEnrollmentCA = true
					in.Settings.CADistributionSettings.IncludeLamassuSystemCA = false
					in.Settings.EnrollmentSettings.EnrollmentCA = enrollCA.ID
				})
				if err != nil {
					t.Fatalf("unexpected error while creating the DMS: %s", err)
				}

				estCli := est.Client{
					Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
					AdditionalPathSegment: dms.ID,
					InsecureSkipVerify:    true,
				}

				caCerts, err := estCli.CACerts(context.Background())

				return caCerts, err
			},
			resultCheck: func(caCerts []*x509.Certificate, err error) {
				if err != nil {
					t.Fatalf("should've not got error but got an error")
				}
				if len(caCerts) != 1 {
					t.Fatalf("should've got only one cacert")
				}

				contains := slices.ContainsFunc(caCerts, func(caCert *x509.Certificate) bool {
					return chelpers.CertificateToPEM(caCert) == chelpers.CertificateToPEM((*x509.Certificate)(enrollCA.Certificate.Certificate))
				})
				if contains != true {
					t.Fatalf("the enrollment ca´s certificate has not been received as cacert")
				}
			},
		},
		{
			name: "OK/IncludingManagedCA",
			run: func() (caCert []*x509.Certificate, err error) {

				dms, err := createDMS(func(in *services.CreateDMSInput) {
					in.Settings.CADistributionSettings.ManagedCAs = []string{caMm.ID}
					in.Settings.EnrollmentSettings.EnrollmentCA = enrollCA.ID
				})
				if err != nil {
					t.Fatalf("unexpected error while creating the DMS: %s", err)
				}

				estCli := est.Client{
					Host:                  fmt.Sprintf("localhost:%d", dmsMgr.Port),
					AdditionalPathSegment: dms.ID,
					InsecureSkipVerify:    true,
				}

				caCerts, err := estCli.CACerts(context.Background())

				return caCerts, err
			},
			resultCheck: func(caCerts []*x509.Certificate, err error) {

				if err != nil {
					t.Fatalf("should've nor got error but got an error")
				}
				if len(caCerts) != 3 {
					t.Fatalf("should've got three cacerts")
				}

				contains := slices.ContainsFunc(caCerts, func(caCert *x509.Certificate) bool {
					return chelpers.CertificateToPEM(caCert) == chelpers.CertificateToPEM((*x509.Certificate)(enrollCA.Certificate.Certificate))
				})
				if contains != true {
					t.Fatalf("the enrollment ca´s certificate has not been received as cacert")
				}

				containsMa := slices.ContainsFunc(caCerts, func(caCert *x509.Certificate) bool {
					return chelpers.CertificateToPEM(caCert) == chelpers.CertificateToPEM((*x509.Certificate)(caMm.Certificate.Certificate))
				})
				if containsMa != true {
					t.Fatalf("the managed ca´s certificate has not been received as cacert")
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
		return testServers.CA.Service.CreateCA(context.Background(), services.CreateCAInput{
			KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 224},
			Subject:            models.Subject{CommonName: name},
			CAExpiration:       models.Validity{Type: models.Duration, Duration: (models.TimeDuration)(lifespanCABootDur)},
			IssuanceExpiration: models.Validity{Type: models.Duration, Duration: (models.TimeDuration)(issuanceCABootDur)},
			Metadata:           map[string]any{},
		})
	}

	createDMS := func(modifier func(in *services.CreateDMSInput)) (*models.DMS, error) {
		input := services.CreateDMSInput{
			ID:       uuid.NewString(),
			Name:     "MyIotFleet",
			Metadata: map[string]any{},
			Settings: models.DMSSettings{
				ServerKeyGen: models.ServerKeyGenSettings{
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
		run         func() (caCert *x509.Certificate, cert *x509.Certificate, csr *x509.CertificateRequest, key any, err error)
		resultCheck func(caCert *x509.Certificate, cert *x509.Certificate, csr *x509.CertificateRequest, key any, err error)
	}{
		{
			name: "OK/ECDSA-256",
			run: func() (caCert *x509.Certificate, cert *x509.Certificate, csr *x509.CertificateRequest, key any, err error) {
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

				bootKey, _ := chelpers.GenerateECDSAKey(elliptic.P224())
				bootCsr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
				bootCrt, err := testServers.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:        bootstrapCA.ID,
					CertRequest: (*models.X509CertificateRequest)(bootCsr),
					IssuanceProfile: models.IssuanceProfile{
						Validity:        bootstrapCA.Validity,
						SignAsCA:        false,
						HonorSubject:    true,
						HonorExtensions: true,
					},
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
				genericKey, _ := chelpers.GenerateECDSAKey(elliptic.P224())
				deviceID := fmt.Sprintf("skeygen-enrolled-device-%s", uuid.NewString())
				enrollCSR, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, genericKey)

				enrollCRT, enrollKey, err := estCli.ServerKeyGen(ctx, enrollCSR)
				if err != nil {
					t.Fatalf("unexpected error while enrolling: %s", err)
				}

				assert.Equal(t, deviceID, enrollCRT.Subject.CommonName)

				serverKeyGen, err := x509.ParsePKCS8PrivateKey(enrollKey)
				if err != nil {
					t.Fatalf("unexpected error while parsing server generated key: %s", err)
				}

				return (*x509.Certificate)(enrollCA.Certificate.Certificate), enrollCRT, enrollCSR, serverKeyGen, nil
			},
			resultCheck: func(caCert, cert *x509.Certificate, csr *x509.CertificateRequest, key any, err error) {
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

				valid, err := chelpers.ValidateCertAndPrivKey(cert, nil, serverKeyGen)
				if err != nil {
					t.Fatalf("could not validate cert and key. Got error: %s", err)
				}

				if !valid {
					t.Fatalf("private key does not match public key")
				}

				if err = helpers.ValidateCertificate(caCert, cert, true); err != nil {
					t.Fatalf("could not validate certificate with CA: %s", err)
				}

				csrPubDerBytes, _ := x509.MarshalPKIXPublicKey(csr.PublicKey)
				crtPubDerBytes, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
				assert.False(t, bytes.Equal(csrPubDerBytes, crtPubDerBytes), "CSR and Cert public keys should not be the same")

			},
		},
		{
			name: "OK/RSA-3072",
			run: func() (caCert *x509.Certificate, cert *x509.Certificate, csr *x509.CertificateRequest, key any, err error) {
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

				bootKey, _ := chelpers.GenerateECDSAKey(elliptic.P224())
				bootCsr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
				bootCrt, err := testServers.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:        bootstrapCA.ID,
					CertRequest: (*models.X509CertificateRequest)(bootCsr),
					IssuanceProfile: models.IssuanceProfile{
						Validity:        bootstrapCA.Validity,
						SignAsCA:        false,
						HonorSubject:    true,
						HonorExtensions: true,
					},
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
				genericKey, _ := chelpers.GenerateECDSAKey(elliptic.P224())
				deviceID := fmt.Sprintf("skeygen-enrolled-device-%s", uuid.NewString())
				enrollCSR, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, genericKey)

				enrollCRT, enrollKey, err := estCli.ServerKeyGen(ctx, enrollCSR)
				if err != nil {
					t.Fatalf("unexpected error while enrolling: %s", err)
				}

				serverKeyGen, err := x509.ParsePKCS8PrivateKey(enrollKey)
				if err != nil {
					t.Fatalf("unexpected error while parsing server generated key: %s", err)
				}

				return (*x509.Certificate)(enrollCA.Certificate.Certificate), enrollCRT, enrollCSR, serverKeyGen, nil
			},
			resultCheck: func(caCert, cert *x509.Certificate, csr *x509.CertificateRequest, key any, err error) {
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

				valid, err := chelpers.ValidateCertAndPrivKey(cert, serverKeyGen, nil)
				if err != nil {
					t.Fatalf("could not validate cert and key. Got error: %s", err)
				}

				if !valid {
					t.Fatalf("private key does not match public key")
				}

				if err = helpers.ValidateCertificate(caCert, cert, true); err != nil {
					t.Fatalf("could not validate certificate with CA: %s", err)
				}

				csrPubDerBytes, _ := x509.MarshalPKIXPublicKey(csr.PublicKey)
				crtPubDerBytes, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
				assert.False(t, bytes.Equal(csrPubDerBytes, crtPubDerBytes), "CSR and Cert public keys should not be the same")
			},
		},
		{
			name: "Err/KeyGenConfigMissing",
			run: func() (caCert *x509.Certificate, cert *x509.Certificate, csr *x509.CertificateRequest, key any, err error) {
				bootstrapCA, err := createCA("boot", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create bootstrap CA: %s", err)
				}

				enrollCA, err := createCA("enroll", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create Enrollment CA: %s", err)
				}

				dms, err := createDMS(func(in *services.CreateDMSInput) {
					in.Settings.ServerKeyGen = models.ServerKeyGenSettings{}
					in.Settings.EnrollmentSettings.EnrollmentCA = enrollCA.ID
					in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsMTLS.ValidationCAs = []string{
						bootstrapCA.ID,
					}
				})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}

				bootKey, _ := chelpers.GenerateECDSAKey(elliptic.P224())
				bootCsr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
				bootCrt, err := testServers.CA.Service.SignCertificate(ctx, services.SignCertificateInput{
					CAID:        bootstrapCA.ID,
					CertRequest: (*models.X509CertificateRequest)(bootCsr),
					IssuanceProfile: models.IssuanceProfile{
						Validity:        bootstrapCA.Validity,
						SignAsCA:        false,
						HonorSubject:    true,
						HonorExtensions: true,
					},
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
				genericKey, _ := chelpers.GenerateECDSAKey(elliptic.P224())
				deviceID := fmt.Sprintf("skeygen-enrolled-device-%s", uuid.NewString())
				enrollCSR, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, genericKey)

				_, _, err = estCli.ServerKeyGen(ctx, enrollCSR)

				return (*x509.Certificate)(enrollCA.Certificate.Certificate), nil, nil, nil, err
			},
			resultCheck: func(caCert, cert *x509.Certificate, csr *x509.CertificateRequest, key any, err error) {
				if err == nil {
					t.Fatalf("Error is expected")
				}

				assert.Contains(t, err.Error(), "server key generation not enabled")
			},
		},
		{
			name: "Err/KeyGenDisabled",
			run: func() (caCert *x509.Certificate, cert *x509.Certificate, csr *x509.CertificateRequest, key any, err error) {
				bootstrapCA, err := createCA("boot", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create bootstrap CA: %s", err)
				}

				enrollCA, err := createCA("enroll", "1y", "1m")
				if err != nil {
					t.Fatalf("could not create Enrollment CA: %s", err)
				}

				dms, err := createDMS(func(in *services.CreateDMSInput) {
					in.Settings.ServerKeyGen.Enabled = false

					in.Settings.EnrollmentSettings.EnrollmentCA = enrollCA.ID
					in.Settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsMTLS.ValidationCAs = []string{
						bootstrapCA.ID,
					}
				})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}

				bootKey, _ := chelpers.GenerateECDSAKey(elliptic.P224())
				bootCsr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
				bootCrt, err := testServers.CA.Service.SignCertificate(ctx, services.SignCertificateInput{
					CAID:        bootstrapCA.ID,
					CertRequest: (*models.X509CertificateRequest)(bootCsr),
					IssuanceProfile: models.IssuanceProfile{
						Validity:        bootstrapCA.Validity,
						SignAsCA:        false,
						HonorSubject:    true,
						HonorExtensions: true,
					},
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
				genericKey, _ := chelpers.GenerateECDSAKey(elliptic.P224())
				deviceID := fmt.Sprintf("skeygen-enrolled-device-%s", uuid.NewString())
				enrollCSR, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, genericKey)

				_, _, err = estCli.ServerKeyGen(ctx, enrollCSR)

				return (*x509.Certificate)(enrollCA.Certificate.Certificate), nil, nil, nil, err
			},
			resultCheck: func(caCert, cert *x509.Certificate, csr *x509.CertificateRequest, key any, err error) {
				if err == nil {
					t.Fatalf("Error is expected")
				}

				assert.Contains(t, err.Error(), "server key generation not enabled")
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
			CAExpiration:       models.Validity{Type: models.Duration, Duration: (models.TimeDuration)(lifespanCABootDur)},
			IssuanceExpiration: models.Validity{Type: models.Duration, Duration: (models.TimeDuration)(issuanceCABootDur)},
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
					RevokeOnReEnrollment:        true,
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

		bootKey, _ := chelpers.GenerateECDSAKey(elliptic.P224())
		bootCsr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "boot-cert"}, bootKey)
		bootCrt, err := testServers.CA.Service.SignCertificate(context.Background(), services.SignCertificateInput{
			CAID:        bootstrapCA.ID,
			CertRequest: (*models.X509CertificateRequest)(bootCsr),
			IssuanceProfile: models.IssuanceProfile{
				Validity:        bootstrapCA.Validity,
				SignAsCA:        false,
				HonorSubject:    true,
				HonorExtensions: true,
			},
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
		enrollKey, _ := chelpers.GenerateRSAKey(2048)
		enrollCSR, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceID}, enrollKey)

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

		valid, err := chelpers.ValidateCertAndPrivKey(cert, priv, nil)
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

				newCsr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceCrt.Subject.CommonName}, deviceKey)

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

				fakeKey, _ := chelpers.GenerateRSAKey(2048)
				fakeCert, _ := chelpers.GenerateSelfSignedCertificate(fakeKey, deviceCrt.Subject.CommonName)

				newCsr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceCrt.Subject.CommonName}, deviceKey)

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

				newCsr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceCrt.Subject.CommonName}, deviceKey)

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

				newCsr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceCrt.Subject.CommonName}, deviceKey)

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

				newCsr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceCrt.Subject.CommonName}, deviceKey)

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

				newCsr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceCrt.Subject.CommonName}, deviceKey)

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

				newCsr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceCrt.Subject.CommonName}, deviceKey)

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

				newCsr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceCrt.Subject.CommonName, Organization: "MyOrg"}, deviceKey)

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

				newCsr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceCrt.Subject.CommonName}, deviceKey)

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
		{
			name: "OK/RevokeOnReEnroll",
			run: func() (caCert *x509.Certificate, cert *x509.Certificate, key any, err error) {
				// First Create a DMS with RevokeOnReEnroll set to true. Old certificate should be revoked
				dms1, _, deviceCrt1, deviceKey1 := prepReenrollScenario(
					func(in *services.CreateDMSInput) {
						in.Settings.ReEnrollmentSettings.RevokeOnReEnrollment = true
					},
					"1m",
				)

				newCsr1, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceCrt1.Subject.CommonName}, deviceKey1)

				estCli := pemESTClient{
					baseEndpoint: fmt.Sprintf("https://localhost:%d/.well-known/est/%s", dmsMgr.Port, dms1.ID),
					cert:         deviceCrt1,
					key:          deviceKey1,
				}

				_, err = estCli.ReEnroll(newCsr1)
				if err != nil {
					t.Fatalf("unexpected error while enrolling: %s", err)
				}

				crt1, err := testServers.CA.Service.GetCertificateBySerialNumber(context.Background(), services.GetCertificatesBySerialNumberInput{
					SerialNumber: helpers.SerialNumberToString(deviceCrt1.SerialNumber),
				})
				if err != nil {
					t.Fatalf("could not get certificate: %s", err)
				}

				if crt1.Status != models.StatusRevoked {
					t.Fatalf("certificate should be revoked")
				}

				if crt1.RevocationReason != ocsp.Superseded {
					t.Fatalf("certificate should be revoked with reason superseded")
				}

				// Second Create a DMS with RevokeOnReEnroll set to false. Old certificate should not be revoked
				dms2, _, deviceCrt2, deviceKey2 := prepReenrollScenario(
					func(in *services.CreateDMSInput) {
						in.Settings.ReEnrollmentSettings.RevokeOnReEnrollment = false
					},
					"1m",
				)

				newCsr2, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: deviceCrt2.Subject.CommonName}, deviceKey1)

				estCli = pemESTClient{
					baseEndpoint: fmt.Sprintf("https://localhost:%d/.well-known/est/%s", dmsMgr.Port, dms2.ID),
					cert:         deviceCrt2,
					key:          deviceKey2,
				}

				_, err = estCli.ReEnroll(newCsr2)
				if err != nil {
					t.Fatalf("unexpected error while enrolling: %s", err)
				}

				crt2, err := testServers.CA.Service.GetCertificateBySerialNumber(context.Background(), services.GetCertificatesBySerialNumberInput{
					SerialNumber: helpers.SerialNumberToString(deviceCrt2.SerialNumber),
				})
				if err != nil {
					t.Fatalf("could not get certificate: %s", err)
				}

				if crt2.Status != models.StatusActive {
					t.Fatalf("certificate should be active")
				}

				return nil, nil, nil, nil
			},
			resultCheck: func(caCert, cert *x509.Certificate, key any, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
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

func TestGetAllDMS(t *testing.T) {
	// t.Parallel()
	devsIds := [3]string{"test1", "test2", "test3"}
	devsIds2 := [3]string{"test11", "test12", "test13"}
	dmsMgr, _, err := StartDMSManagerServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create DMS Manager test server: %s", err)
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
		run         func() ([]models.DMS, error)
		resultCheck func(dmss []models.DMS, err error)
	}{
		{
			name: "OK/ExhaustiveRunTrue",
			run: func() ([]models.DMS, error) {
				dmss := []models.DMS{}
				_, err = createDMS(func(in *services.CreateDMSInput) {
					in.ID = devsIds[0]
				})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}

				_, err = createDMS(func(in *services.CreateDMSInput) {
					in.ID = devsIds[1]
				})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}
				_, err = createDMS(func(in *services.CreateDMSInput) {
					in.ID = devsIds[2]
				})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}
				request := services.GetAllInput{
					ListInput: resources.ListInput[models.DMS]{
						QueryParameters: &resources.QueryParameters{
							PageSize: 2,
							Sort: resources.SortOptions{
								SortMode:  resources.SortModeAsc,
								SortField: "id",
							},
						},
						ExhaustiveRun: true,
						ApplyFunc: func(dms models.DMS) {
							dmss = append(dmss, dms)
						},
					},
				}

				bookmark, err := dmsMgr.HttpDeviceManagerSDK.GetAll(context.Background(), request)

				fmt.Println(bookmark)

				return dmss, err
			},
			resultCheck: func(dmss []models.DMS, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}
				if len(dmss) != 3 {
					t.Fatalf("the amount of the DMS should be 3, insted got it: %d", len(dmss))
				}
			},
		},
		{
			name: "Err/ExhaustiveRunFalse",
			run: func() ([]models.DMS, error) {
				dmss := []models.DMS{}
				_, err = createDMS(func(in *services.CreateDMSInput) {
					in.ID = devsIds2[0]
				})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}

				_, err = createDMS(func(in *services.CreateDMSInput) {
					in.ID = devsIds2[1]
				})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}
				_, err = createDMS(func(in *services.CreateDMSInput) {
					in.ID = devsIds2[2]
				})
				if err != nil {
					t.Fatalf("could not create DMS: %s", err)
				}
				request := services.GetAllInput{
					ListInput: resources.ListInput[models.DMS]{
						QueryParameters: &resources.QueryParameters{
							PageSize: 2,
							Sort: resources.SortOptions{
								SortMode:  resources.SortModeAsc,
								SortField: "id",
							},
						},
						ExhaustiveRun: false,
						ApplyFunc: func(dms models.DMS) {
							dmss = append(dmss, dms)
						},
					},
				}

				bookmark, err := dmsMgr.HttpDeviceManagerSDK.GetAll(context.Background(), request)

				fmt.Println(bookmark)

				return dmss, err
			},
			resultCheck: func(dmss []models.DMS, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}
				if len(dmss) != 2 {
					t.Fatalf("the amount of the DMS should be 2, insted got it: %d", len(dmss))
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
	keyPem, err := chelpers.PrivateKeyToPEM(c.key)
	if err != nil {
		return nil, err
	}

	cer, err := tls.X509KeyPair([]byte(chelpers.CertificateToPEM(c.cert)), []byte(keyPem))
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

	cert, err := chelpers.ParseCertificate(string(b))
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func startWebhookServer() (*gin.Engine, string, func(), error) {
	// Create a custom HTTP handler
	router := gin.Default()

	// Listen on a random free port
	listener, err := net.Listen("tcp", ":0") // :0 to choose a random port
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to listen on a random port: %w", err)
	}

	addr := listener.Addr().String()
	re := regexp.MustCompile(`:(\d+)$`)
	match := re.FindStringSubmatch(addr)
	var port string
	if len(match) > 1 {
		port = ":" + match[1] // Capture group 1
	}

	url := fmt.Sprintf("http://localhost%s", port)

	// Create an HTTP server
	server := &http.Server{
		Handler: router,
	}

	go func() {
		if err := server.Serve(listener); err != nil {
			log.Printf("Server error: %v", err)
		}
	}()

	shutdown := func() {
		log.Println("Shutting down the server...")
		if err := server.Shutdown(context.Background()); err != nil {
			log.Printf("Server forced to shutdown: %v", err)
		}
	}

	return router, url, shutdown, nil
}
