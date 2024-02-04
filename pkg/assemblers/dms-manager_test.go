package assemblers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"github.com/globalsign/est"
	"github.com/google/uuid"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
)

func StartDMSManagerServiceTestServer(t *testing.T) (*DMSManagerTestServer, *TestServer, error) {
	storageConfig, err := PreparePostgresForTest([]string{"ca", "devicemanager", "dmsmanager"})
	if err != nil {
		t.Fatalf("could not prepare Postgres test server: %s", err)
	}
	cryptoConfig := PrepareCryptoEnginesForTest([]CryptoEngine{GOLANG})
	testServer, err := AssembleServices(storageConfig, cryptoConfig, []Service{CA, DEVICE_MANAGER, DMS_MANAGER})
	if err != nil {
		t.Fatalf("could not assemble Server with HTTP server")
	}
	err = testServer.BeforeEach()
	if err != nil {
		t.Fatalf("could not run 'BeforeEach' cleanup func in test case: %s", err)
	}

	t.Cleanup(testServer.AfterSuite)

	return testServer.DMSManager, testServer, nil
}

func TestCreateDMS(t *testing.T) {
	dmsMgr, _, err := StartDMSManagerServiceTestServer(t)
	if err != nil {
		t.Fatalf("could not create DMS Manager test server: %s", err)
	}

	dmsSample := services.CreateDMSInput{
		ID:   "1234-5678",
		Name: "MyIotFleet",
	}
	dms, err := dmsMgr.Service.CreateDMS(context.Background(), dmsSample)
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
	t.Parallel()
	dmsMgr, testServers, err := StartDMSManagerServiceTestServer(t)
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
						AuthMode: models.ESTAuthModeClientCertificate,
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
		run         func() (cert *x509.Certificate, key any, err error)
		resultCheck func(cert *x509.Certificate, key any, err error)
	}{
		{
			name: "OK/ECDSA",
			run: func() (cert *x509.Certificate, key any, err error) {
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

				return enrollCRT, enrollKey, nil
			},
			resultCheck: func(cert *x509.Certificate, key any, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}

				priv, ok := key.(*ecdsa.PrivateKey)
				if !ok {
					t.Fatalf("could not cast priv key into ECDSA")
				}

				pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
				if !ok {
					t.Fatalf("could not cast pub key into ECDSA")
				}

				if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
					t.Fatalf("private key does not match public key")
				}
			},
		},
		{
			name: "OK/RSA",
			run: func() (cert *x509.Certificate, key any, err error) {
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

				return enrollCRT, enrollKey, nil
			},
			resultCheck: func(cert *x509.Certificate, key any, err error) {
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}

				priv, ok := key.(*rsa.PrivateKey)
				if !ok {
					t.Fatalf("could not cast priv key into RSA")
				}

				pub, ok := cert.PublicKey.(*rsa.PublicKey)
				if !ok {
					t.Fatalf("could not cast pub key into RSA")
				}

				if pub.N.Cmp(priv.N) != 0 {
					t.Fatalf("private key does not match public key")
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
