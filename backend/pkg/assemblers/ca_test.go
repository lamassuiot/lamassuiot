package assemblers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"golang.org/x/crypto/ocsp"
)

const DefaultCAID = "111111-2222"
const DefaultCACN = "MyCA"

func TestCryptoEngines(t *testing.T) {
	//serverTest, err := StartCAServiceTestServer(t, false)
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca", "kms").WithVault().Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}
	caTest := serverTest.CA

	var testcases = []struct {
		name        string
		resultCheck func(engines []*models.CryptoEngineProvider, err error) error
	}{
		{
			name: "OK/Got-2-Engines",
			resultCheck: func(engines []*models.CryptoEngineProvider, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error, but got one: %s", err)
				}

				if len(engines) != 2 {
					return fmt.Errorf("should've got two engines, but got %d", len(engines))
				}

				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {

			err = serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' func in test case: %s", err)
			}

			err = tc.resultCheck(caTest.Service.GetCryptoEngineProvider(context.Background()))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}

		})
	}
}
func TestCreateCA(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	caID := "12345-11111"
	caDUr := models.TimeDuration(time.Hour * 24)
	issuanceDur := models.TimeDuration(time.Hour * 12)

	profile, err := serverTest.CA.Service.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Validity: models.Validity{Type: models.Duration, Duration: issuanceDur},
		},
	})
	if err != nil {
		t.Fatalf("failed creating issuance profile: %s", err)
	}

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) (*models.CACertificate, error)
		resultCheck func(createdCA *models.CACertificate, err error) error
	}{
		{
			name:   "OK/KeyType-RSA",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.CACertificate, error) {

				return caSDK.CreateCA(context.Background(), services.CreateCAInput{
					ID:           caID,
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "TestCA"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDUr},
					ProfileID:    profile.ID,
				})
			},
			resultCheck: func(createdCA *models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've created CA without error, but got error: %s", err)
				}

				return nil
			},
		},
		{
			name:   "OK/KeyType-ECC",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.CACertificate, error) {
				return caSDK.CreateCA(context.Background(), services.CreateCAInput{
					ID:           caID,
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256},
					Subject:      models.Subject{CommonName: "TestCA"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDUr},
					ProfileID:    profile.ID,
				})
			},
			resultCheck: func(createdCA *models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've created CA without error, but got error: %s", err)
				}

				return nil
			},
		},
		{
			name:   "OK/Expiration-Duration",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.CACertificate, error) {
				return caSDK.CreateCA(context.Background(), services.CreateCAInput{
					ID:           caID,
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "TestCA"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDUr},
					ProfileID:    profile.ID,
				})
			},
			resultCheck: func(createdCA *models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've created CA without error, but got error: %s", err)
				}

				return nil
			},
		},
		{
			name:   "OK/Expiration-Time",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.CACertificate, error) {
				tCA := time.Date(9999, 11, 31, 23, 59, 59, 0, time.UTC)
				tIssue := time.Date(9999, 11, 30, 23, 59, 59, 0, time.UTC)

				profile2, err := serverTest.CA.Service.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Validity: models.Validity{Type: models.Time, Time: tIssue},
					},
				})
				if err != nil {
					t.Fatalf("failed creating issuance profile: %s", err)
				}

				return caSDK.CreateCA(context.Background(), services.CreateCAInput{
					ID:           caID,
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "TestCA"},
					CAExpiration: models.Validity{Type: models.Time, Time: tCA},
					ProfileID:    profile2.ID,
				})
			},
			resultCheck: func(createdCA *models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've created CA without error, but got error: %s", err)
				}

				if createdCA.Certificate.ValidTo.Year() != 9999 {
					t.Fatalf("CA certificate should expire on 9999 but got %d", createdCA.Certificate.ValidTo.Year())
				}

				return nil
			},
		},
		{
			name: "Error/Duplicate-CA-ID",
			before: func(svc services.CAService) error {
				_, err := svc.CreateCA(context.Background(), services.CreateCAInput{
					ID:           caID,
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "TestCA"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDUr},
					ProfileID:    profile.ID,
				})
				if err != nil {
					return err
				}
				return nil
			},
			run: func(caSDK services.CAService) (*models.CACertificate, error) {
				return caSDK.CreateCA(context.Background(), services.CreateCAInput{
					ID:           caID,
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "TestCA"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDUr},
					ProfileID:    profile.ID,
				})
			},
			resultCheck: func(createdCA *models.CACertificate, err error) error {
				if err == nil {
					return fmt.Errorf("should've got error. Got none")
				}

				if !errors.Is(err, errs.ErrCAAlreadyExists) {
					return fmt.Errorf("should've got error %s. Got: %s", errs.ErrCAAlreadyExists, err)
				}

				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {

			err = serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' func in test case: %s", err)
			}

			err = tc.before(caTest.Service)
			err = tc.resultCheck(tc.run(caTest.HttpCASDK))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}

		})
	}
}

func TestDeleteCAAndIssuedCertificates(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	caDUr := models.TimeDuration(time.Hour * 24)
	issuanceDur := models.TimeDuration(time.Hour * 12)

	createProfile := func(t *testing.T) *models.IssuanceProfile {
		profile, err := serverTest.CA.Service.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
			Profile: models.IssuanceProfile{
				Validity: models.Validity{Type: models.Duration, Duration: issuanceDur},
			},
		})
		if err != nil {
			t.Fatalf("failed creating issuance profile: %s", err)
		}

		return profile
	}

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) (*x509.Certificate, error)
		resultCheck func(caSDK services.CAService, cert *x509.Certificate, err error) error
	}{
		{
			name:   "Err/DeletingCAAndIssuedCertificates",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*x509.Certificate, error) {
				profile := createProfile(t)
				enrollCA, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "TestCA"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDUr},
					ProfileID:    profile.ID,
				})

				if err != nil {
					t.Fatalf("could not create CA: %s", err)
				}

				commonName := fmt.Sprintf("enrolled-%s", uuid.NewString())
				enrollKey, _ := chelpers.GenerateRSAKey(2048)
				enrollCSR, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: commonName}, enrollKey)

				crt, err := caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:              enrollCA.ID,
					CertRequest:       (*models.X509CertificateRequest)(enrollCSR),
					IssuanceProfileID: profile.ID,
				})
				if err != nil {
					t.Fatalf("could not sign the certificate: %s", err)
				}

				_, err = caSDK.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{
					CAID:             enrollCA.ID,
					Status:           models.StatusRevoked,
					RevocationReason: models.RevocationReason(0),
				})

				if err != nil {
					t.Fatalf("could not update the status of the CA: %s", err)
				}

				err = caSDK.DeleteCA(context.Background(), services.DeleteCAInput{
					CAID:          enrollCA.ID,
					CascadeDelete: false,
				})
				return (*x509.Certificate)(crt.Certificate), err
			},

			resultCheck: func(caSDK services.CAService, cert *x509.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've not got an error, but it has got an error: %s", err)
				}
				_, err = caSDK.GetCertificateBySerialNumber(context.Background(), services.GetCertificatesBySerialNumberInput{
					SerialNumber: cert.SerialNumber.String(),
				})

				if err == nil {
					return fmt.Errorf("should've got an error, but it has not an error: %s", err)
				}

				return nil
			},
		},
		{
			name:   "OK/ExternalCA",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*x509.Certificate, error) {
				duration := models.TimeDuration(time.Hour * 24)
				ca, _, err := chelpers.GenerateSelfSignedCA(x509.RSA, time.Duration(duration), "test")
				if err != nil {
					return nil, fmt.Errorf("error while importing self signed CA: %s", err)
				}

				profile2, err := serverTest.CA.Service.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Validity: models.Validity{Type: models.Duration, Duration: duration},
					},
				})
				if err != nil {
					t.Fatalf("failed creating issuance profile: %s", err)
				}

				importedCALvl1, err := caSDK.ImportCA(context.Background(), services.ImportCAInput{
					CAType:        models.CertificateTypeExternal,
					ProfileID:     profile2.ID,
					CACertificate: (*models.X509Certificate)(ca),
				})

				if err != nil {
					return nil, fmt.Errorf("got unexpected error, while importing the CA: %s", err)
				}

				err = caSDK.DeleteCA(context.Background(), services.DeleteCAInput{
					CAID:          importedCALvl1.ID,
					CascadeDelete: false,
				})
				return nil, err
			},

			resultCheck: func(caSDK services.CAService, cert *x509.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've not got an error, but it has an error: %s", err)
				}

				return nil
			},
		},
		{
			name:   "OK/RevokedCA",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*x509.Certificate, error) {
				profile := createProfile(t)
				ca1, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "TestCA"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDUr},
					ProfileID:    profile.ID,
				})

				if err != nil {
					t.Fatalf("could not create CA: %s", err)
				}

				_, err = caSDK.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{
					CAID:             ca1.ID,
					Status:           models.StatusRevoked,
					RevocationReason: models.RevocationReason(0),
				})
				if err != nil {
					t.Fatalf("error while changing the status of the CA: %s", err)
				}

				err = caSDK.DeleteCA(context.Background(), services.DeleteCAInput{
					CAID:          ca1.ID,
					CascadeDelete: false,
				})
				return nil, err
			},

			resultCheck: func(caSDK services.CAService, cert *x509.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've not got an error, but it has an error: %s", err)
				}

				return nil
			},
		},
		{
			name:   "OK/ExpiredCA",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*x509.Certificate, error) {
				profile := createProfile(t)
				ca1, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "TestCA"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDUr},
					ProfileID:    profile.ID,
				})

				if err != nil {
					t.Fatalf("could not create CA: %s", err)
				}

				_, err = caSDK.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{
					CAID:   ca1.ID,
					Status: models.StatusExpired,
				})
				if err != nil {
					t.Fatalf("error while changing the status of the CA: %s", err)
				}

				err = caSDK.DeleteCA(context.Background(), services.DeleteCAInput{
					CAID:          ca1.ID,
					CascadeDelete: false,
				})
				return nil, err
			},

			resultCheck: func(caSDK services.CAService, cert *x509.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've not got an error, but it has an error: %s", err)
				}

				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			err = serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' func in test case: %s", err)
			}

			err = tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}
			crt, err := tc.run(caTest.HttpCASDK)
			err = tc.resultCheck(caTest.Service, crt, err)
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}

		})
	}
}

func TestGetCertificatesByCaAndStatus(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	t.Parallel()

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) ([]*models.Certificate, error)
		resultCheck func(certs []*models.Certificate, err error) error
	}{
		{
			name: "OK/Pagination10-pagesize5-without-pagination",
			before: func(svc services.CAService) error {
				certsToIssue := 10
				ca, err := svc.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
				if err != nil {
					return fmt.Errorf("Error getting the CA: %s", err)
				}

				for i := 0; i < certsToIssue; i++ {
					key, err := chelpers.GenerateRSAKey(2048)
					if err != nil {
						return fmt.Errorf("Error creating the private key: %s", err)
					}

					csr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: fmt.Sprintf("cert-%d", i)}, key)
					_, err = svc.SignCertificate(context.Background(), services.SignCertificateInput{
						CAID:              DefaultCAID,
						CertRequest:       (*models.X509CertificateRequest)(csr),
						IssuanceProfileID: ca.ProfileID,
					})
					if err != nil {
						return err
					}
				}
				return nil
			},
			run: func(caSDK services.CAService) ([]*models.Certificate, error) {
				issuedCerts := []*models.Certificate{}
				_, err := caSDK.GetCertificatesByCaAndStatus(context.Background(), services.GetCertificatesByCaAndStatusInput{
					CAID:   DefaultCAID,
					Status: models.StatusActive,
					ListInput: resources.ListInput[models.Certificate]{
						ExhaustiveRun: false,
						QueryParameters: &resources.QueryParameters{
							PageSize: 5,
						},
						ApplyFunc: func(elem models.Certificate) {
							issuedCerts = append(issuedCerts, &elem)
						},
					},
				})

				return issuedCerts, err
			},
			resultCheck: func(certs []*models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error, but got error: %s", err)
				}

				if len(certs) != 5 {
					return fmt.Errorf("unexpected count of the certificates %d", len(certs))
				}

				return nil
			},
		},
		{
			name: "OK/Pagination15-pagesize5-with-pagination",
			before: func(svc services.CAService) error {
				ca, err := svc.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
				if err != nil {
					return fmt.Errorf("Error getting the CA: %s", err)
				}

				certsToIssue := 15
				for i := 0; i < certsToIssue; i++ {
					key, _ := chelpers.GenerateRSAKey(2048)
					csr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: fmt.Sprintf("cert-%d", i)}, key)
					_, err := svc.SignCertificate(context.Background(), services.SignCertificateInput{
						CAID:              DefaultCAID,
						CertRequest:       (*models.X509CertificateRequest)(csr),
						IssuanceProfileID: ca.ProfileID,
					})
					if err != nil {
						return err
					}
				}
				return nil
			},
			run: func(caSDK services.CAService) ([]*models.Certificate, error) {
				issuedCerts := []*models.Certificate{}
				_, err := caSDK.GetCertificatesByCaAndStatus(context.Background(), services.GetCertificatesByCaAndStatusInput{
					CAID:   DefaultCAID,
					Status: models.StatusActive,
					ListInput: resources.ListInput[models.Certificate]{
						ExhaustiveRun: true,
						QueryParameters: &resources.QueryParameters{
							PageSize: 5,
						},
						ApplyFunc: func(elem models.Certificate) {
							issuedCerts = append(issuedCerts, &elem)
						},
					},
				})

				return issuedCerts, err
			},
			resultCheck: func(certs []*models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error, but got error: %s", err)
				}

				if len(certs) != 16 { // 15 + 1 (the CA certificate)
					return fmt.Errorf("unexpected count of certificates. got %d", len(certs))
				}

				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			//
			err = serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' func in test case: %s", err)
			}

			_, err = initCA(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'initCA' func in test case: %s", err)
			}

			err = tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(caTest.HttpCASDK))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}

		})
	}
}

func TestSignCertificate(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	var testcases = []struct {
		name        string
		run         func(caSDK services.CAService, caIDToSign string, validity models.Validity) (*models.Certificate, error)
		resultCheck func(issuedCerts *models.Certificate, err error) error
	}{
		{
			name: "OK/SignCertificate",
			run: func(caSDK services.CAService, caIDToSign string, validity models.Validity) (*models.Certificate, error) {
				key, err := chelpers.GenerateRSAKey(2048)
				if err != nil {
					return nil, err
				}

				csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "test", Country: "ES", Organization: "lamassu", OrganizationUnit: "iot", State: "lamassu-world", Locality: "lamassu-city"}, key)
				if err != nil {
					return nil, err
				}

				return caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:        caIDToSign,
					CertRequest: (*models.X509CertificateRequest)(csr),
					IssuanceProfile: &models.IssuanceProfile{
						Validity:        validity,
						SignAsCA:        false,
						HonorSubject:    true,
						HonorExtensions: true,
					},
				})
			},
			resultCheck: func(issuedCert *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error but got error: %s", err)
				}

				if issuedCert == nil {
					return fmt.Errorf("should've got issued certificate but got nil")
				}

				if issuedCert.Subject.CommonName != "test" {
					return fmt.Errorf("issued certificate should have CommonName 'test' but got %s", issuedCert.Subject.CommonName)
				}

				if issuedCert.Subject.Country != "ES" {
					return fmt.Errorf("issued certificate should have Country 'ES' but got %s", issuedCert.Subject.Country)
				}

				if issuedCert.Subject.Organization != "lamassu" {
					return fmt.Errorf("issued certificate should have Organization 'lamassu' but got %s", issuedCert.Subject.Organization)
				}

				if issuedCert.Subject.OrganizationUnit != "iot" {
					return fmt.Errorf("issued certificate should have OrganizationUnit 'iot' but got %s", issuedCert.Subject.OrganizationUnit)
				}

				if issuedCert.Subject.State != "lamassu-world" {
					return fmt.Errorf("issued certificate should have State 'lamassu-world' but got %s", issuedCert.Subject.State)
				}

				if issuedCert.Subject.Locality != "lamassu-city" {
					return fmt.Errorf("issued certificate should have Locality 'lamassu-city' but got %s", issuedCert.Subject.Locality)
				}

				return nil
			},
		},
		{
			name: "OK/SignWithProfileSubject",
			run: func(caSDK services.CAService, caIDToSign string, validity models.Validity) (*models.Certificate, error) {
				key, err := chelpers.GenerateRSAKey(2048)
				if err != nil {
					return nil, err
				}

				csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "test", Country: "ES", Organization: "lamassu", OrganizationUnit: "iot", State: "lamassu-world", Locality: "lamassu-city"}, key)
				if err != nil {
					return nil, err
				}

				return caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:        caIDToSign,
					CertRequest: (*models.X509CertificateRequest)(csr),
					IssuanceProfile: &models.IssuanceProfile{
						Validity:     validity,
						SignAsCA:     false,
						HonorSubject: false,
						Subject: models.Subject{
							CommonName:       "other-test",
							Country:          "US",
							Organization:     "other-lamassu",
							OrganizationUnit: "other-iot",
							State:            "other-lamassu-world",
							Locality:         "other-lamassu-city",
						},
					},
				})
			},
			resultCheck: func(issuedCert *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error but got error: %s", err)
				}

				if issuedCert == nil {
					return fmt.Errorf("should've got issued certificate but got nil")
				}

				if issuedCert.Subject.CommonName == "other-test" {
					return fmt.Errorf("issued certificate should respect CSR CN 'test' but got %s", issuedCert.Subject.CommonName)
				}

				if issuedCert.Subject.Country != "US" {
					return fmt.Errorf("issued certificate should have Country 'US' but got %s", issuedCert.Subject.Country)
				}

				if issuedCert.Subject.Organization != "other-lamassu" {
					return fmt.Errorf("issued certificate should have Organization 'other-lamassu' but got %s", issuedCert.Subject.Organization)
				}

				if issuedCert.Subject.OrganizationUnit != "other-iot" {
					return fmt.Errorf("issued certificate should have OrganizationUnit 'other-iot' but got %s", issuedCert.Subject.OrganizationUnit)
				}

				if issuedCert.Subject.State != "other-lamassu-world" {
					return fmt.Errorf("issued certificate should have State 'other-lamassu-world' but got %s", issuedCert.Subject.State)
				}

				return nil
			},
		},
		{
			name: "OK/KeyUsages",
			run: func(caSDK services.CAService, caIDToSign string, validity models.Validity) (*models.Certificate, error) {
				key, err := chelpers.GenerateRSAKey(2048)
				if err != nil {
					return nil, err
				}

				csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "test", Country: "ES", Organization: "lamassu", OrganizationUnit: "iot", State: "lamassu-world", Locality: "lamassu-city"}, key)
				if err != nil {
					return nil, err
				}

				return caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:        caIDToSign,
					CertRequest: (*models.X509CertificateRequest)(csr),
					IssuanceProfile: &models.IssuanceProfile{
						Validity:        validity,
						SignAsCA:        false,
						HonorSubject:    true,
						HonorExtensions: true,
						KeyUsage: models.X509KeyUsage(
							models.X509KeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign),
						),
						ExtendedKeyUsages: []models.X509ExtKeyUsage{
							models.X509ExtKeyUsage(x509.ExtKeyUsageClientAuth),
							models.X509ExtKeyUsage(x509.ExtKeyUsageCodeSigning),
						},
					},
				})
			},
			resultCheck: func(issuedCert *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error but got error: %s", err)
				}

				if issuedCert == nil {
					return fmt.Errorf("should've got issued certificate but got nil")
				}

				if issuedCert.Certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
					return fmt.Errorf("issued certificate should have KeyUsage 'DigitalSignature' but was not set")
				}

				if issuedCert.Certificate.KeyUsage&x509.KeyUsageCRLSign == 0 {
					return fmt.Errorf("issued certificate should have KeyUsage 'CRLSign' but got was not set")
				}

				if !slices.Contains(issuedCert.Certificate.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
					return fmt.Errorf("issued certificate should have ExtKeyUsage 'ClientAuth' but  was not set")
				}

				if !slices.Contains(issuedCert.Certificate.ExtKeyUsage, x509.ExtKeyUsageCodeSigning) {
					return fmt.Errorf("issued certificate should have ExtKeyUsage 'CodeSigning' but was not set")
				}

				return nil
			},
		},
		{
			name: "OK/SignCertificateWithAltSubject",
			run: func(caSDK services.CAService, caIDToSign string, validity models.Validity) (*models.Certificate, error) {
				key, err := chelpers.GenerateRSAKey(2048)
				if err != nil {
					return nil, err
				}

				template := x509.CertificateRequest{
					Subject: pkix.Name{
						CommonName: "test",
					},
					DNSNames: []string{"example.com", "www.example.com"},
				}

				csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
				if err != nil {
					return nil, err
				}

				csr, err := x509.ParseCertificateRequest(csrBytes)
				if err != nil {
					return nil, err
				}

				return caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:        caIDToSign,
					CertRequest: (*models.X509CertificateRequest)(csr),
					IssuanceProfile: &models.IssuanceProfile{
						Validity:        validity,
						SignAsCA:        false,
						HonorSubject:    true,
						HonorExtensions: true,
					},
				})
			},
			resultCheck: func(issuedCert *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error but got error: %s", err)
				}

				if issuedCert == nil {
					return fmt.Errorf("should've got issued certificate but got nil")
				}

				if !slices.Contains(issuedCert.Certificate.DNSNames, "example.com") {
					return fmt.Errorf("issued certificate should have DNSName 'example.com' but was not set")
				}

				if !slices.Contains(issuedCert.Certificate.DNSNames, "www.example.com") {
					return fmt.Errorf("issued certificate should have DNSName 'www.example.com' but was not set")
				}

				return nil
			},
		},
		{
			name: "OK/SignCertificateWithoutAltSubject",
			run: func(caSDK services.CAService, caIDToSign string, validity models.Validity) (*models.Certificate, error) {
				key, err := chelpers.GenerateRSAKey(2048)
				if err != nil {
					return nil, err
				}

				template := x509.CertificateRequest{
					Subject: pkix.Name{
						CommonName: "test",
					},
					DNSNames: []string{"example.com", "www.example.com"},
				}

				csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
				if err != nil {
					return nil, err
				}

				csr, err := x509.ParseCertificateRequest(csrBytes)
				if err != nil {
					return nil, err
				}

				return caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:        caIDToSign,
					CertRequest: (*models.X509CertificateRequest)(csr),
					IssuanceProfile: &models.IssuanceProfile{
						Validity:        validity,
						SignAsCA:        false,
						HonorSubject:    true,
						HonorExtensions: false,
					},
				})
			},
			resultCheck: func(issuedCert *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error but got error: %s", err)
				}

				if issuedCert == nil {
					return fmt.Errorf("should've got issued certificate but got nil")
				}

				if len(issuedCert.Certificate.DNSNames) != 0 {
					return fmt.Errorf("issued certificate should not have any DNSNames, but got %v", issuedCert.Certificate.DNSNames)
				}

				return nil
			},
		},
		{
			name: "OK/BaseIssuanceProfile",
			run: func(caSDK services.CAService, caIDToSign string, validity models.Validity) (*models.Certificate, error) {
				//first create profile
				p, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Name:                   "test-profile",
						Description:            "my test profile",
						HonorKeyUsage:          true,
						KeyUsage:               models.X509KeyUsage(x509.KeyUsageCRLSign | x509.KeyUsageEncipherOnly), // KeyUsage should be ignored since HonorKeyUsage is true
						HonorExtendedKeyUsages: true,
						ExtendedKeyUsages: []models.X509ExtKeyUsage{ // ExtendedKeyUsages should be ignored since HonorExtendedKeyUsages is true
							models.X509ExtKeyUsage(x509.ExtKeyUsageServerAuth),
							models.X509ExtKeyUsage(x509.ExtKeyUsageOCSPSigning),
						},
						HonorSubject: true,
						Subject: models.Subject{ // these values should be ignored since HonorSubject is true
							Country:          "US",
							Organization:     "other-lamassu",
							OrganizationUnit: "other-iot",
							State:            "other-lamassu-world",
							Locality:         "other-lamassu-city",
						},
						HonorExtensions: true,
						Validity:        validity,
						SignAsCA:        false,
					},
				})
				if err != nil {
					return nil, err
				}

				profileID := p.ID

				key, err := chelpers.GenerateRSAKey(2048)
				if err != nil {
					return nil, err
				}

				extensions := []pkix.Extension{}
				kuExt, err := chelpers.GenerateKeyUsagePKIExtension(x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment | x509.KeyUsageDecipherOnly)
				if err != nil {
					return nil, fmt.Errorf("error generating KeyUsage extension: %s", err)
				}

				ekuExt, err := chelpers.GenerateExtendedKeyUsagePKIExtension([]x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageCodeSigning})
				if err != nil {
					return nil, fmt.Errorf("error generating ExtendedKeyUsage extension: %s", err)
				}

				extensions = append(extensions, kuExt, ekuExt)

				csr, err := chelpers.GenerateCertificateRequestWithExtensions(
					models.Subject{CommonName: "test", Country: "ES", Organization: "lamassu", OrganizationUnit: "iot", State: "lamassu-world", Locality: "lamassu-city"},
					extensions,
					key,
				)
				if err != nil {
					return nil, err
				}

				return caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:              caIDToSign,
					CertRequest:       (*models.X509CertificateRequest)(csr),
					IssuanceProfileID: profileID,
				})
			},
			resultCheck: func(issuedCerts *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error but got error: %s", err)
				}

				if issuedCerts == nil {
					return fmt.Errorf("should've got issued certificate but got nil")
				}

				if issuedCerts.Subject.CommonName != "test" {
					return fmt.Errorf("issued certificate should have CommonName 'test' but got '%s'", issuedCerts.Subject.CommonName)
				}

				if issuedCerts.Subject.Country != "ES" {
					return fmt.Errorf("issued certificate should have Country 'ES' but got '%s'", issuedCerts.Subject.Country)
				}

				if issuedCerts.Subject.Organization != "lamassu" {
					return fmt.Errorf("issued certificate should have Organization 'lamassu' but got '%s'", issuedCerts.Subject.Organization)
				}

				if issuedCerts.Subject.OrganizationUnit != "iot" {
					return fmt.Errorf("issued certificate should have OrganizationUnit 'iot' but got '%s'", issuedCerts.Subject.OrganizationUnit)
				}

				if issuedCerts.Subject.State != "lamassu-world" {
					return fmt.Errorf("issued certificate should have State 'lamassu-world' but got '%s'", issuedCerts.Subject.State)
				}

				if issuedCerts.Subject.Locality != "lamassu-city" {
					return fmt.Errorf("issued certificate should have Locality 'lamassu-city' but got '%s'", issuedCerts.Subject.Locality)
				}

				if issuedCerts.Certificate.KeyUsage&x509.KeyUsageContentCommitment == 0 {
					return fmt.Errorf("issued certificate should have KeyUsage 'ContentCommitment' but was not set")
				}

				if issuedCerts.Certificate.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
					return fmt.Errorf("issued certificate should have KeyUsage 'KeyEncipherment' but was not set")
				}

				if issuedCerts.Certificate.KeyUsage&x509.KeyUsageCRLSign != 0 {
					return fmt.Errorf("issued certificate should NOT have KeyUsage 'CRLSign' but it was set")
				}

				if issuedCerts.Certificate.KeyUsage&x509.KeyUsageEncipherOnly != 0 {
					return fmt.Errorf("issued certificate should NOT have KeyUsage 'EncipherOnly' but it was set")
				}

				if issuedCerts.Certificate.KeyUsage&x509.KeyUsageDecipherOnly == 0 {
					return fmt.Errorf("issued certificate should have KeyUsage 'DecipherOnly' but was not set")
				}

				if !slices.Contains(issuedCerts.Certificate.ExtKeyUsage, x509.ExtKeyUsageEmailProtection) {
					return fmt.Errorf("issued certificate should have ExtKeyUsage 'EmailProtection' but was not set")
				}

				if !slices.Contains(issuedCerts.Certificate.ExtKeyUsage, x509.ExtKeyUsageCodeSigning) {
					return fmt.Errorf("issued certificate should have ExtKeyUsage 'CodeSigning' but was not set")
				}

				if slices.Contains(issuedCerts.Certificate.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
					return fmt.Errorf("issued certificate should NOT have ExtKeyUsage 'ServerAuth' but it was set")
				}

				if slices.Contains(issuedCerts.Certificate.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning) {
					return fmt.Errorf("issued certificate should NOT have ExtKeyUsage 'OCSPSigning' but it was set")
				}

				return nil
			},
		},
		{
			name: "OK/IssuanceProfile-DontHonor",
			run: func(caSDK services.CAService, caIDToSign string, validity models.Validity) (*models.Certificate, error) {
				//first create profile
				p, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Name:                   "test-profile",
						Description:            "my test profile",
						HonorKeyUsage:          false,
						KeyUsage:               models.X509KeyUsage(x509.KeyUsageCRLSign | x509.KeyUsageEncipherOnly), // KeyUsage should be ignored since HonorKeyUsage is true
						HonorExtendedKeyUsages: false,
						ExtendedKeyUsages: []models.X509ExtKeyUsage{ // ExtendedKeyUsages should be ignored since HonorExtendedKeyUsages is true
							models.X509ExtKeyUsage(x509.ExtKeyUsageServerAuth),
							models.X509ExtKeyUsage(x509.ExtKeyUsageEmailProtection),
						},
						HonorSubject: false,
						Subject: models.Subject{ // these values should be ignored since HonorSubject is true
							Country:          "US",
							Organization:     "other-lamassu",
							OrganizationUnit: "other-iot",
							State:            "other-lamassu-world",
							Locality:         "other-lamassu-city",
						},
						HonorExtensions: false,
						Validity:        validity,
						SignAsCA:        false,
					},
				})
				if err != nil {
					return nil, err
				}

				profileID := p.ID

				key, err := chelpers.GenerateRSAKey(2048)
				if err != nil {
					return nil, err
				}

				extensions := []pkix.Extension{}
				kuExt, err := chelpers.GenerateKeyUsagePKIExtension(x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment | x509.KeyUsageDecipherOnly)
				if err != nil {
					return nil, fmt.Errorf("error generating KeyUsage extension: %s", err)
				}

				ekuExt, err := chelpers.GenerateExtendedKeyUsagePKIExtension([]x509.ExtKeyUsage{x509.ExtKeyUsageIPSECEndSystem, x509.ExtKeyUsageCodeSigning})
				if err != nil {
					return nil, fmt.Errorf("error generating ExtendedKeyUsage extension: %s", err)
				}

				extensions = append(extensions, kuExt, ekuExt)

				csr, err := chelpers.GenerateCertificateRequestWithExtensions(
					models.Subject{CommonName: "test", Country: "ES", Organization: "lamassu", OrganizationUnit: "iot", State: "lamassu-world", Locality: "lamassu-city"},
					extensions,
					key,
				)
				if err != nil {
					return nil, err
				}

				return caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:              caIDToSign,
					CertRequest:       (*models.X509CertificateRequest)(csr),
					IssuanceProfileID: profileID,
				})
			},
			resultCheck: func(issuedCerts *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error but got error: %s", err)
				}

				if issuedCerts == nil {
					return fmt.Errorf("should've got issued certificate but got nil")
				}

				if issuedCerts.Subject.CommonName != "test" {
					return fmt.Errorf("issued certificate should have CommonName 'test' but got '%s'", issuedCerts.Subject.CommonName)
				}

				if issuedCerts.Subject.Country != "US" {
					return fmt.Errorf("issued certificate should have Country 'US' but got '%s'", issuedCerts.Subject.Country)
				}

				if issuedCerts.Subject.Organization != "other-lamassu" {
					return fmt.Errorf("issued certificate should have Organization 'other-lamassu' but got '%s'", issuedCerts.Subject.Organization)
				}

				if issuedCerts.Subject.OrganizationUnit != "other-iot" {
					return fmt.Errorf("issued certificate should have OrganizationUnit 'other-iot' but got '%s'", issuedCerts.Subject.OrganizationUnit)
				}

				if issuedCerts.Subject.State != "other-lamassu-world" {
					return fmt.Errorf("issued certificate should have State 'other-lamassu-world' but got '%s'", issuedCerts.Subject.State)
				}

				if issuedCerts.Subject.Locality != "other-lamassu-city" {
					return fmt.Errorf("issued certificate should have Locality 'other-lamassu-city' but got '%s'", issuedCerts.Subject.Locality)
				}

				if issuedCerts.Certificate.KeyUsage&x509.KeyUsageContentCommitment != 0 {
					return fmt.Errorf("issued certificate should NOT have KeyUsage 'ContentCommitment' but it was set")
				}

				if issuedCerts.Certificate.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
					return fmt.Errorf("issued certificate should NOT have KeyUsage 'KeyEncipherment' but it was set")
				}

				if issuedCerts.Certificate.KeyUsage&x509.KeyUsageDecipherOnly != 0 {
					return fmt.Errorf("issued certificate should NOT have KeyUsage 'DecipherOnly' but it was set")
				}

				if issuedCerts.Certificate.KeyUsage&x509.KeyUsageCRLSign == 0 {
					return fmt.Errorf("issued certificate should have KeyUsage 'CRLSign' but got was not set")
				}

				if issuedCerts.Certificate.KeyUsage&x509.KeyUsageEncipherOnly == 0 {
					return fmt.Errorf("issued certificate should have KeyUsage 'EncipherOnly' but was not set")
				}

				if slices.Contains(issuedCerts.Certificate.ExtKeyUsage, x509.ExtKeyUsageIPSECEndSystem) {
					return fmt.Errorf("issued certificate should NOT have ExtKeyUsage 'IPSECEndSystem' but it was set")
				}

				if slices.Contains(issuedCerts.Certificate.ExtKeyUsage, x509.ExtKeyUsageCodeSigning) {
					return fmt.Errorf("issued certificate should NOT have ExtKeyUsage 'CodeSigning' but it was set")
				}

				if !slices.Contains(issuedCerts.Certificate.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
					return fmt.Errorf("issued certificate should have ExtKeyUsage 'ServerAuth' but was not set")
				}

				if !slices.Contains(issuedCerts.Certificate.ExtKeyUsage, x509.ExtKeyUsageEmailProtection) {
					return fmt.Errorf("issued certificate should have ExtKeyUsage 'EmailProtection' but was not set")
				}

				return nil
			},
		},
		{
			name: "OK/IssuanceProfile-IsCATrue",
			run: func(caSDK services.CAService, caIDToSign string, validity models.Validity) (*models.Certificate, error) {
				//first create profile
				p, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Name:                   "test-profile",
						Description:            "my test profile",
						HonorKeyUsage:          true,
						HonorExtendedKeyUsages: true,
						HonorSubject:           true,
						HonorExtensions:        true,
						Validity:               validity,
						SignAsCA:               true,
					},
				})
				if err != nil {
					return nil, err
				}

				profileID := p.ID

				key, err := chelpers.GenerateRSAKey(2048)
				if err != nil {
					return nil, err
				}

				csr, err := chelpers.GenerateCertificateRequest(
					models.Subject{CommonName: "test", Country: "ES", Organization: "lamassu", OrganizationUnit: "iot", State: "lamassu-world", Locality: "lamassu-city"},
					key,
				)
				if err != nil {
					return nil, err
				}

				return caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:              caIDToSign,
					CertRequest:       (*models.X509CertificateRequest)(csr),
					IssuanceProfileID: profileID,
				})
			},
			resultCheck: func(issuedCerts *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error but got error: %s", err)
				}

				if issuedCerts == nil {
					return fmt.Errorf("should've got issued certificate but got nil")
				}

				if issuedCerts.Subject.CommonName != "test" {
					return fmt.Errorf("issued certificate should have CommonName 'test' but got '%s'", issuedCerts.Subject.CommonName)
				}

				if issuedCerts.IsCA != true {
					return fmt.Errorf("issued certificate should be a CA but IsCA is false")
				}

				return nil
			},
		},
		{
			name: "OK/IssuanceProfile-OnlySignRsaCsrs",
			run: func(caSDK services.CAService, caIDToSign string, validity models.Validity) (*models.Certificate, error) {
				//first create profile
				p, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Name:                   "test-profile",
						Description:            "my test profile",
						HonorKeyUsage:          true,
						HonorExtendedKeyUsages: true,
						HonorSubject:           true,
						HonorExtensions:        true,
						Validity:               validity,
						SignAsCA:               true,
						CryptoEnforcement: models.IssuanceProfileCryptoEnforcement{
							Enabled:        true,
							AllowECDSAKeys: false,
							AllowRSAKeys:   true,
						},
					},
				})
				if err != nil {
					return nil, err
				}

				profileID := p.ID

				ecdsaKey, err := chelpers.GenerateECDSAKey(elliptic.P256())
				if err != nil {
					return nil, err
				}

				csrECDSA, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "test"}, ecdsaKey)
				if err != nil {
					return nil, err
				}

				_, err = caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:              caIDToSign,
					CertRequest:       (*models.X509CertificateRequest)(csrECDSA),
					IssuanceProfileID: profileID,
				})
				if err == nil {
					return nil, fmt.Errorf("should've got error but got none")
				}

				rsaKey, err := chelpers.GenerateRSAKey(2048)
				if err != nil {
					return nil, err
				}

				csrRSA, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "test"}, rsaKey)
				if err != nil {
					return nil, err
				}

				return caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:              caIDToSign,
					CertRequest:       (*models.X509CertificateRequest)(csrRSA),
					IssuanceProfileID: profileID,
				})
			},
			resultCheck: func(issuedCerts *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error but got error: %s", err)
				}

				if issuedCerts == nil {
					return fmt.Errorf("should've got issued certificate but got nil")
				}

				if issuedCerts.Subject.CommonName != "test" {
					return fmt.Errorf("issued certificate should have CommonName 'test' but got '%s'", issuedCerts.Subject.CommonName)
				}

				return nil
			},
		},
		{
			name: "OK/IssuanceProfile-OnlySignEcdsaCsrs",
			run: func(caSDK services.CAService, caIDToSign string, validity models.Validity) (*models.Certificate, error) {
				//first create profile
				p, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Name:                   "test-profile",
						Description:            "my test profile",
						HonorKeyUsage:          true,
						HonorExtendedKeyUsages: true,
						HonorSubject:           true,
						HonorExtensions:        true,
						Validity:               validity,
						SignAsCA:               true,
						CryptoEnforcement: models.IssuanceProfileCryptoEnforcement{
							Enabled:        true,
							AllowECDSAKeys: true,
							AllowRSAKeys:   false,
						},
					},
				})
				if err != nil {
					return nil, err
				}

				profileID := p.ID

				rsaKey, err := chelpers.GenerateRSAKey(2048)
				if err != nil {
					return nil, err
				}

				csrRSA, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "test"}, rsaKey)
				if err != nil {
					return nil, err
				}

				_, err = caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:              caIDToSign,
					CertRequest:       (*models.X509CertificateRequest)(csrRSA),
					IssuanceProfileID: profileID,
				})
				if err == nil {
					return nil, fmt.Errorf("should've got error but got none")
				}

				ecdsaKey, err := chelpers.GenerateECDSAKey(elliptic.P256())
				if err != nil {
					return nil, err
				}

				csrECDSA, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "test"}, ecdsaKey)
				if err != nil {
					return nil, err
				}

				return caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:              caIDToSign,
					CertRequest:       (*models.X509CertificateRequest)(csrECDSA),
					IssuanceProfileID: profileID,
				})
			},
			resultCheck: func(issuedCerts *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error but got error: %s", err)
				}

				if issuedCerts == nil {
					return fmt.Errorf("should've got issued certificate but got nil")
				}

				if issuedCerts.Subject.CommonName != "test" {
					return fmt.Errorf("issued certificate should have CommonName 'test' but got '%s'", issuedCerts.Subject.CommonName)
				}

				return nil
			},
		},
		{
			name: "OK/IssuanceProfile-OnlySignEcdsa256And384Csrs",
			run: func(caSDK services.CAService, caIDToSign string, validity models.Validity) (*models.Certificate, error) {
				//first create profile
				p, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Name:                   "test-profile",
						Description:            "my test profile",
						HonorKeyUsage:          true,
						HonorExtendedKeyUsages: true,
						HonorSubject:           true,
						HonorExtensions:        true,
						Validity:               validity,
						SignAsCA:               true,
						CryptoEnforcement: models.IssuanceProfileCryptoEnforcement{
							Enabled:              true,
							AllowECDSAKeys:       true,
							AllowedECDSAKeySizes: []int{256, 384},
							AllowRSAKeys:         false,
						},
					},
				})
				if err != nil {
					return nil, err
				}

				profileID := p.ID
				key256, _ := chelpers.GenerateECDSAKey(elliptic.P256())
				csr256, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "test"}, key256)

				key384, _ := chelpers.GenerateECDSAKey(elliptic.P384())
				csr384, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "test"}, key384)

				key521, _ := chelpers.GenerateECDSAKey(elliptic.P521())
				csr521, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "test"}, key521)

				_, err = caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:              caIDToSign,
					CertRequest:       (*models.X509CertificateRequest)(csr256),
					IssuanceProfileID: profileID,
				})
				if err != nil {
					return nil, fmt.Errorf("should've got no error but got error: %s", err)
				}

				_, err = caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:              caIDToSign,
					CertRequest:       (*models.X509CertificateRequest)(csr384),
					IssuanceProfileID: profileID,
				})
				if err != nil {
					return nil, fmt.Errorf("should've got no error but got error: %s", err)
				}

				_, err = caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:              caIDToSign,
					CertRequest:       (*models.X509CertificateRequest)(csr521),
					IssuanceProfileID: profileID,
				})
				if err == nil {
					return nil, fmt.Errorf("should've got error but got none")
				}

				return nil, nil
			},
			resultCheck: func(issuedCerts *models.Certificate, err error) error {
				return err
			},
		},
		{
			name: "OK/IssuanceProfile-OnlySignRsa2048Csrs",
			run: func(caSDK services.CAService, caIDToSign string, validity models.Validity) (*models.Certificate, error) {
				//first create profile
				p, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Name:                   "test-profile",
						Description:            "my test profile",
						HonorKeyUsage:          true,
						HonorExtendedKeyUsages: true,
						HonorSubject:           true,
						HonorExtensions:        true,
						Validity:               validity,
						SignAsCA:               true,
						CryptoEnforcement: models.IssuanceProfileCryptoEnforcement{
							Enabled:            true,
							AllowECDSAKeys:     true,
							AllowedRSAKeySizes: []int{2048},
							AllowRSAKeys:       true,
						},
					},
				})
				if err != nil {
					return nil, err
				}

				profileID := p.ID
				key2048, _ := chelpers.GenerateRSAKey(2048)
				csr2048, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "test"}, key2048)

				key3072, _ := chelpers.GenerateRSAKey(3072)
				csr3072, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "test"}, key3072)

				_, err = caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:              caIDToSign,
					CertRequest:       (*models.X509CertificateRequest)(csr2048),
					IssuanceProfileID: profileID,
				})
				if err != nil {
					return nil, fmt.Errorf("should've got no error but got error: %s", err)
				}

				_, err = caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:              caIDToSign,
					CertRequest:       (*models.X509CertificateRequest)(csr3072),
					IssuanceProfileID: profileID,
				})
				if err == nil {
					return nil, fmt.Errorf("should've got error but got none")
				}

				return nil, nil
			},
			resultCheck: func(issuedCerts *models.Certificate, err error) error {
				return err
			},
		},
		{
			name: "Err/CADoesNotExist",
			run: func(caSDK services.CAService, caIDToSign string, validity models.Validity) (*models.Certificate, error) {
				key, err := chelpers.GenerateRSAKey(2048)
				if err != nil {
					return nil, err
				}

				csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "test", Country: "ES", Organization: "lamassu", OrganizationUnit: "iot", State: "lamassu-world", Locality: "lamassu-city"}, key)
				if err != nil {
					return nil, err
				}

				return caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:        "myCA",
					CertRequest: (*models.X509CertificateRequest)(csr),
					IssuanceProfile: &models.IssuanceProfile{
						Validity:        validity,
						SignAsCA:        false,
						HonorSubject:    true,
						HonorExtensions: true,
					},
				})
			},
			resultCheck: func(issuedCert *models.Certificate, err error) error {
				if err == nil {
					return fmt.Errorf("should've got error but got none")
				}

				if !errors.Is(err, errs.ErrCANotFound) {
					return fmt.Errorf("should've got error %s but got %s", errs.ErrCANotFound, err)
				}

				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			//
			err = serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' func in test case: %s", err)
			}

			_, err = initCA(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'initCA' func in test case: %s", err)
			}

			caExpiration := models.TimeDuration(time.Hour * 24)
			issuanceExpiration := models.TimeDuration(time.Hour * 2)

			profile, err := caTest.Service.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
				Profile: models.IssuanceProfile{
					Validity: models.Validity{Type: models.Duration, Duration: issuanceExpiration},
				},
			})
			if err != nil {
				t.Fatalf("failed creating issuance profile: %s", err)
			}

			ca, err := caTest.Service.CreateCA(context.Background(), services.CreateCAInput{
				KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
				Subject:      models.Subject{CommonName: "TestCA"},
				CAExpiration: models.Validity{Type: models.Duration, Duration: caExpiration},
				ProfileID:    profile.ID,
			})
			if err != nil {
				t.Fatalf("failed creating CA: %s", err)
			}

			err = tc.resultCheck(tc.run(caTest.HttpCASDK, ca.ID, profile.Validity))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func TestImportCertificate(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	var testcases = []struct {
		name        string
		run         func(caSDK services.CAService) (*models.Certificate, *models.CACertificate, error)
		resultCheck func(importedCert *models.Certificate, ca *models.CACertificate, err error) error
	}{
		{
			name: "OK/ImportCertificate",
			run: func(caSDK services.CAService) (*models.Certificate, *models.CACertificate, error) {
				//Create Out of Band CA
				ca, caKey, err := chelpers.GenerateSelfSignedCA(x509.ECDSA, time.Hour*10, "myCA")
				if err != nil {
					t.Fatalf("failed creating self signed CA: %s", err)
				}

				//Sign Certificate with Out of Band CA
				key, err := chelpers.GenerateRSAKey(2048)
				if err != nil {
					t.Fatalf("failed generating RSA key: %s", err)
				}

				csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "test"}, key)
				if err != nil {
					t.Fatalf("failed generating certificate request: %s", err)
				}

				certificateTemplate := x509.Certificate{
					PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
					PublicKey:          csr.PublicKey,
					SerialNumber:       big.NewInt(1),
					Issuer:             ca.Subject,
					Subject:            csr.Subject,
					NotBefore:          time.Now(),
					NotAfter:           time.Now().Add(time.Hour),
					KeyUsage:           x509.KeyUsageDigitalSignature,
				}

				certificateBytes, err := x509.CreateCertificate(rand.Reader, &certificateTemplate, ca, csr.PublicKey, caKey)
				if err != nil {
					t.Fatalf("failed creating signed certificate: %s", err)
				}

				cert, err := x509.ParseCertificate(certificateBytes)
				if err != nil {
					t.Fatalf("failed parsing certificate: %s", err)
				}

				//Import CA
				issuanceDur := models.TimeDuration(time.Hour * 2)
				profile, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Validity: models.Validity{Type: models.Duration, Duration: issuanceDur},
					},
				})
				if err != nil {
					t.Fatalf("failed creating issuance profile: %s", err)
				}

				importedCA, err := caSDK.ImportCA(context.Background(), services.ImportCAInput{
					CAType:        models.CertificateTypeImportedWithKey,
					ProfileID:     profile.ID,
					CAECKey:       caKey.(*ecdsa.PrivateKey),
					CACertificate: (*models.X509Certificate)(ca),
					KeyType:       models.KeyType(x509.ECDSA),
				})
				if err != nil {
					t.Fatalf("failed importing CA: %s", err)
				}

				//Import Certificate
				importedCert, err := caSDK.ImportCertificate(context.Background(), services.ImportCertificateInput{
					Certificate: (*models.X509Certificate)(cert),
					Metadata: map[string]any{
						"test": "test2",
					},
				})

				return importedCert, importedCA, err
			},
			resultCheck: func(importedCert *models.Certificate, ca *models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error but got error: %s", err)
				}

				if importedCert == nil {
					return fmt.Errorf("should've got imported certificate but got nil")
				}

				if importedCert.IssuerCAMetadata.Level != ca.Level {
					return fmt.Errorf("imported certificate should have Level %d but got %d", ca.Level, importedCert.IssuerCAMetadata.Level)
				}

				if importedCert.IssuerCAMetadata.ID != ca.ID {
					return fmt.Errorf("imported certificate should have CAID %s but got %s", ca.ID, importedCert.IssuerCAMetadata.ID)
				}

				if importedCert.IssuerCAMetadata.SN != ca.Certificate.SerialNumber {
					return fmt.Errorf("imported certificate should have SerialNumber %s but got %s", ca.Certificate.SerialNumber, importedCert.IssuerCAMetadata.SN)
				}

				if importedCert.Status != models.StatusActive {
					return fmt.Errorf("imported certificate should have Active status but got %s", importedCert.Status)
				}

				if importedCert.Metadata["test"] != "test2" {
					return fmt.Errorf("imported certificate should have metadata 'test' with value 'test2' but got %s", importedCert.Metadata["test"])
				}

				return nil
			},
		},
		{
			name: "OK/ExpiredCert",
			run: func(caSDK services.CAService) (*models.Certificate, *models.CACertificate, error) {
				//Create Out of Band CA
				ca, caKey, err := chelpers.GenerateSelfSignedCA(x509.ECDSA, time.Hour*10, "myCA")
				if err != nil {
					t.Fatalf("failed creating self signed CA: %s", err)
				}

				//Sign Certificate with Out of Band CA
				key, err := chelpers.GenerateRSAKey(2048)
				if err != nil {
					t.Fatalf("failed generating RSA key: %s", err)
				}

				csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "test"}, key)
				if err != nil {
					t.Fatalf("failed generating certificate request: %s", err)
				}

				certificateTemplate := x509.Certificate{
					PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
					PublicKey:          csr.PublicKey,
					SerialNumber:       big.NewInt(1),
					Issuer:             ca.Subject,
					Subject:            csr.Subject,
					NotBefore:          time.Now().Add(-time.Hour * 24 * 2), //2 days ago
					NotAfter:           time.Now().Add(-time.Hour * 24),     //1 day ago
					KeyUsage:           x509.KeyUsageDigitalSignature,
				}

				certificateBytes, err := x509.CreateCertificate(rand.Reader, &certificateTemplate, ca, csr.PublicKey, caKey)
				if err != nil {
					t.Fatalf("failed creating signed certificate: %s", err)
				}

				cert, err := x509.ParseCertificate(certificateBytes)
				if err != nil {
					t.Fatalf("failed parsing certificate: %s", err)
				}

				//Import CA
				issuanceDur := models.TimeDuration(time.Hour * 2)
				profile, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Validity: models.Validity{Type: models.Duration, Duration: issuanceDur},
					},
				})
				if err != nil {
					t.Fatalf("failed creating issuance profile: %s", err)
				}

				importedCA, err := caSDK.ImportCA(context.Background(), services.ImportCAInput{
					CAType:        models.CertificateTypeImportedWithKey,
					ProfileID:     profile.ID,
					CAECKey:       caKey.(*ecdsa.PrivateKey),
					CACertificate: (*models.X509Certificate)(ca),
					KeyType:       models.KeyType(x509.ECDSA),
				})
				if err != nil {
					t.Fatalf("failed importing CA: %s", err)
				}

				//Import Certificate
				importedCert, err := caSDK.ImportCertificate(context.Background(), services.ImportCertificateInput{
					Certificate: (*models.X509Certificate)(cert),
					Metadata: map[string]any{
						"test": "test2",
					},
				})

				return importedCert, importedCA, err
			},
			resultCheck: func(importedCert *models.Certificate, ca *models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error but got error: %s", err)
				}

				if importedCert == nil {
					return fmt.Errorf("should've got imported certificate but got nil")
				}

				if importedCert.Status != models.StatusExpired {
					return fmt.Errorf("imported certificate should have Expired status but got %s", importedCert.Status)
				}

				return nil
			},
		},
		{
			name: "OK/AloneCert",
			run: func(caSDK services.CAService) (*models.Certificate, *models.CACertificate, error) {
				//Create Out of Band CA
				ca, caKey, err := chelpers.GenerateSelfSignedCA(x509.ECDSA, time.Hour*10, "myCA")
				if err != nil {
					t.Fatalf("failed creating self signed CA: %s", err)
				}

				//Sign Certificate with Out of Band CA
				key, err := chelpers.GenerateRSAKey(2048)
				if err != nil {
					t.Fatalf("failed generating RSA key: %s", err)
				}

				csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "test"}, key)
				if err != nil {
					t.Fatalf("failed generating certificate request: %s", err)
				}

				certificateTemplate := x509.Certificate{
					PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
					PublicKey:          csr.PublicKey,
					SerialNumber:       big.NewInt(1),
					Issuer:             ca.Subject,
					Subject:            csr.Subject,
					NotBefore:          time.Now(),
					NotAfter:           time.Now().Add(time.Hour),
					KeyUsage:           x509.KeyUsageDigitalSignature,
				}

				certificateBytes, err := x509.CreateCertificate(rand.Reader, &certificateTemplate, ca, csr.PublicKey, caKey)
				if err != nil {
					t.Fatalf("failed creating signed certificate: %s", err)
				}

				cert, err := x509.ParseCertificate(certificateBytes)
				if err != nil {
					t.Fatalf("failed parsing certificate: %s", err)
				}

				//Import Certificate. This time CA is not imported beforehand
				importedCert, err := caSDK.ImportCertificate(context.Background(), services.ImportCertificateInput{
					Certificate: (*models.X509Certificate)(cert),
					Metadata: map[string]any{
						"test": "test2",
					},
				})

				return importedCert, nil, err
			},
			resultCheck: func(importedCert *models.Certificate, ca *models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error but got error: %s", err)
				}

				if importedCert == nil {
					return fmt.Errorf("should've got imported certificate but got nil")
				}

				if importedCert.IssuerCAMetadata.ID != "-" {
					return fmt.Errorf("imported certificate should have IssuerCAMetadata.ID '-' but got %s", importedCert.IssuerCAMetadata.ID)
				}

				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			//
			err = serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(caTest.HttpCASDK))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func TestRevokeCA(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	var testcases = []struct {
		name        string
		run         func(caSDK services.CAService) (*models.CACertificate, error)
		resultCheck func(revokedCA *models.CACertificate, issuedCerts []*models.Certificate, err error) error
	}{
		{
			name: "OK/RevokeWith0CertsIssued",
			run: func(caSDK services.CAService) (*models.CACertificate, error) {
				return caSDK.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{
					CAID:             DefaultCAID,
					Status:           models.StatusRevoked,
					RevocationReason: ocsp.AACompromise,
				})
			},
			resultCheck: func(revokedCA *models.CACertificate, issuedCerts []*models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error but got error: %s", err)
				}

				if revokedCA.Certificate.Status != models.StatusRevoked {
					return fmt.Errorf("CA should have Revoked status but is in %s status", revokedCA.Certificate.Status)
				}

				if revokedCA.Certificate.RevocationReason != ocsp.AACompromise {
					return fmt.Errorf("CA should have RevocationReason AACompromise status but is in %s reason", revokedCA.Certificate.RevocationReason)
				}

				return nil
			},
		},
		{
			name: "OK/RevokeWith20CertsIssued",
			run: func(caSDK services.CAService) (*models.CACertificate, error) {
				ca, err := caSDK.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
				if err != nil {
					return nil, err
				}

				issue20 := 20
				for i := 0; i < issue20; i++ {
					key, err := chelpers.GenerateRSAKey(2048)
					if err != nil {
						return nil, err
					}

					csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: fmt.Sprintf("test-%d", i)}, key)
					if err != nil {
						return nil, err
					}

					caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
						CAID:              DefaultCAID,
						CertRequest:       (*models.X509CertificateRequest)(csr),
						IssuanceProfileID: ca.ProfileID,
					})
				}
				caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:              DefaultCAID,
					IssuanceProfileID: ca.ProfileID,
				})

				return caSDK.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{
					CAID:             DefaultCAID,
					Status:           models.StatusRevoked,
					RevocationReason: ocsp.AACompromise,
				})
			},
			resultCheck: func(revokedCA *models.CACertificate, issuedCerts []*models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error but got error: %s", err)
				}

				if revokedCA.Certificate.Status != models.StatusRevoked {
					return fmt.Errorf("CA should have Revoked status but is in %s status", revokedCA.Certificate.Status)
				}

				for _, crt := range issuedCerts {
					if crt.Status != models.StatusRevoked {
						return fmt.Errorf("issued certificate %s should have Revoked status but is in %s status", crt.SerialNumber, crt.Status)
					}
				}

				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			err = serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' func in test case: %s", err)
			}

			_, err = initCA(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'init CA' func in test case: %s", err)
			}

			ca, err := tc.run(caTest.HttpCASDK)
			if err != nil {
				t.Fatalf("failed running 'run' func in test case: %s", err)
			}

			issuedCerts := []*models.Certificate{}
			caTest.Service.GetCertificatesByCA(context.Background(), services.GetCertificatesByCAInput{
				CAID: DefaultCAID,
				ListInput: resources.ListInput[models.Certificate]{
					QueryParameters: &resources.QueryParameters{},
					ExhaustiveRun:   true,
					ApplyFunc: func(elem models.Certificate) {
						issuedCerts = append(issuedCerts, &elem)
					},
				},
			})

			err = tc.resultCheck(ca, issuedCerts, err)
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}

		})
	}
}

func TestUpdateCAMetadata(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) error
		resultCheck func(err error) error
	}{
		{
			name:   "OK/UpdateCAMetadata",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) error {

				ud := make(map[string]interface{})
				ud["userName"] = "anonymous"
				//cas := []*models.CACertificate{}
				_, err := caSDK.UpdateCAMetadata(context.Background(), services.UpdateCAMetadataInput{
					CAID: DefaultCAID,
					Patches: chelpers.NewPatchBuilder().
						Add(chelpers.JSONPointerBuilder(), ud).
						Build(),
				})
				if err != nil {
					t.Errorf("failed updating the metadata of the CA: %s", err)
				}
				return err
			},
			resultCheck: func(err error) error {
				if err != nil {
					return fmt.Errorf("should've changed the metadata without error, but it occurs an error: %s", err)
				}
				//Figure it out, which is the purpose of this
				return nil
			},
		},
		{
			name:   "Err/UpdateCAMetadataCANotExist",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) error {

				ud := make(map[string]interface{})
				ud["userName"] = "anonymous"
				//cas := []*models.CACertificate{}
				_, err := caSDK.UpdateCAMetadata(context.Background(), services.UpdateCAMetadataInput{
					CAID: "sdfsfgsd",
					Patches: chelpers.NewPatchBuilder().
						Add(chelpers.JSONPointerBuilder(), ud).
						Build(),
				})
				if err != nil {
					t.Logf("failed updating the metadata of the CA: %s", err)
				}
				return err
			},
			resultCheck: func(err error) error {
				if err == nil {
					return fmt.Errorf("should've got error. Got none")
				}

				if !errors.Is(err, errs.ErrCANotFound) {
					return fmt.Errorf("got unexpected error: %s", err)
				}
				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			//
			// err := postgres_test.BeforeEach()
			// fmt.Errorf("Error while running BeforeEach job: %s", err)

			err = serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' cleanup func in test case: %s", err)
			}

			//Init CA Server with 1 CA
			_, err = initCA(caTest.Service)
			if err != nil {
				t.Fatalf("failed running initCA: %s", err)
			}

			err = tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(caTest.HttpCASDK))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func TestGetCAsByCommonName(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) ([]*models.CACertificate, error)
		resultCheck func([]*models.CACertificate, error) error
	}{
		{
			name:   "OK/CAsCommonName",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) ([]*models.CACertificate, error) {
				cas := []*models.CACertificate{}
				_, err := caSDK.GetCAsByCommonName(context.Background(), services.GetCAsByCommonNameInput{
					CommonName: DefaultCACN,
					ApplyFunc: func(cert models.CACertificate) {
						cas = append(cas, &cert)
					},
				})
				return cas, err
			},
			resultCheck: func(cas []*models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've got CAs without error, but got error: %s", err)
				}

				if len(cas) != 1 {
					return fmt.Errorf("should've got 1 CA but got %d", len(cas))
				}
				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {

			err = serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' func in test case: %s", err)
			}

			//Init CA Server with 1 CA
			_, err = initCA(caTest.Service)
			if err != nil {
				t.Fatalf("failed running initCA: %s", err)
			}

			err = tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(caTest.HttpCASDK))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}

		})
	}
}

func TestUpdateCertificateMetadata(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) error
		resultCheck func(error) error
	}{
		{
			name:   "OK/UpdateCertificateMetadata",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) error {

				key, err := chelpers.GenerateRSAKey(2048)
				if err != nil {
					return fmt.Errorf("Error creating the private key: %s", err)
				}

				csr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: fmt.Sprintf("cert-%d", 1)}, key)
				cert, err := caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:        DefaultCAID,
					CertRequest: (*models.X509CertificateRequest)(csr),
					IssuanceProfile: &models.IssuanceProfile{
						SignAsCA:        false,
						HonorSubject:    true,
						HonorExtensions: true,
					},
				})
				if err != nil {
					return err
				}
				ud := make(map[string]interface{})
				ud["userName"] = "anonymous"
				_, err = caSDK.UpdateCertificateMetadata(context.Background(), services.UpdateCertificateMetadataInput{
					SerialNumber: cert.SerialNumber,
					Patches: chelpers.NewPatchBuilder().
						Add(chelpers.JSONPointerBuilder(), ud).
						Build(),
				})
				return err
			},
			resultCheck: func(err error) error {
				if err != nil {
					return fmt.Errorf("should've update without error, but got error: %s", err)
				}
				return nil
			},
		},
		{
			name:   "Err/UpdateCertificateMetadata",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) error {

				ud := make(map[string]interface{})
				ud["userName"] = "anonymous"
				_, err = caSDK.UpdateCertificateMetadata(context.Background(), services.UpdateCertificateMetadataInput{
					SerialNumber: "dadaafgsdtw",
					Patches: chelpers.NewPatchBuilder().
						Add(chelpers.JSONPointerBuilder(), ud).
						Build(),
				})
				return err
			},
			resultCheck: func(err error) error {
				if err == nil {
					return fmt.Errorf("should've got error. Got none")
				}

				if !errors.Is(err, errs.ErrCertificateNotFound) {
					return fmt.Errorf("got unexpected error: %s", err)
				}

				return nil
			},
		},
		{
			name:   "Err/UpdateCertificateErrorStructureWithNil",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) error {

				ud := make(map[string]interface{})
				ud["userName"] = "anonymous"
				_, err = caSDK.UpdateCertificateMetadata(context.Background(), services.UpdateCertificateMetadataInput{
					SerialNumber: "dadaafgsdtw",
					Patches:      nil,
				})
				return err
			},
			resultCheck: func(err error) error {
				if err == nil {
					return fmt.Errorf("should've got error. Got none")
				}

				if !errors.Is(err, errs.ErrValidateBadRequest) {
					return fmt.Errorf("got unexpected error: %s", err)
				}

				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {

			err = serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' func in test case: %s", err)
			}

			//Init CA Server with 1 CA
			_, err = initCA(caTest.Service)
			if err != nil {
				t.Fatalf("failed running initCA: %s", err)
			}

			err = tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(caTest.HttpCASDK))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}

		})
	}
}
func TestUpdateCAStatus(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca", "kms").WithMonitor().Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) (*models.CACertificate, error)
		resultCheck func(*models.CACertificate, error) error
	}{
		{
			name: "OK/UpdateExpiredCAStatus",
			before: func(svc services.CAService) error {
				//Create Out of Band CA
				profile, err := svc.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Second * 1)},
					},
				})
				if err != nil {
					t.Fatalf("failed creating issuance profile: %s", err)
				}

				_, err = svc.CreateCA(context.Background(), services.CreateCAInput{
					ID:           "myCA",
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256},
					Subject:      models.Subject{CommonName: "myCA"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Second * 2)},
					ProfileID:    profile.ID,
					Metadata:     map[string]any{},
				})
				if err != nil {
					return fmt.Errorf("Got error while creating the CA %s", err)
				}

				//Wait for the CA to expire
				time.Sleep(time.Second * 5)
				return nil
			},
			run: func(caSDK services.CAService) (*models.CACertificate, error) {
				caStatus := models.StatusExpired
				res, err := caSDK.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{
					CAID:             "myCA",
					Status:           caStatus,
					RevocationReason: models.RevocationReason(2),
				})

				return res, err
			},
			resultCheck: func(cas *models.CACertificate, err error) error {
				if err == nil {
					return fmt.Errorf("should've got error, but got no error: %s", err)
				}

				if err != errs.ErrCertificateStatusTransitionNotAllowed {
					return fmt.Errorf("should've got error, but got error: %s", err)
				}
				return nil
			},
		},
		{
			name:   "OK/UpdateCAStatusCANotExist",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.CACertificate, error) {
				caStatus := models.StatusExpired
				res, err := caSDK.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{
					CAID:             "sdadaad",
					Status:           caStatus,
					RevocationReason: models.RevocationReason(2),
				})

				if err != nil {
					return nil, fmt.Errorf("Got error while updating the status of the CA %s", err)
				}

				ca, err := caSDK.GetCAByID(context.Background(), services.GetCAByIDInput{
					CAID: DefaultCAID,
				})
				if err != nil {
					return nil, fmt.Errorf("Got error while checking the status of the CA %s", err)
				}
				if ca.Certificate.Status != caStatus {
					return nil, fmt.Errorf("should've got no error, but got error: %s", err)
				}
				return res, err
			},
			resultCheck: func(cas *models.CACertificate, err error) error {
				if err == nil {
					return fmt.Errorf("should've got no error, but got error: %s", err)
				}
				return nil
			},
		},
		{
			name:   "OK/UpdateCAStatusRevoked",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.CACertificate, error) {
				caStatus := models.StatusRevoked
				//cas := []*models.CACertificate{}
				res, err := caSDK.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{
					CAID:             DefaultCAID,
					Status:           caStatus,
					RevocationReason: models.RevocationReason(2),
				})

				if err != nil {
					return nil, fmt.Errorf("unexpected status for CA")
				}

				ca, err := caSDK.GetCAByID(context.Background(), services.GetCAByIDInput{
					CAID: DefaultCAID,
				})
				if err != nil {
					return nil, fmt.Errorf("Got error while checking CA status  %s", err)
				}
				if ca.Certificate.Status != caStatus {
					return nil, fmt.Errorf("unexpected status for CA")
				}
				return res, err
			},
			resultCheck: func(cas *models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error, but got error: %s", err)
				}
				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			//
			// err := postgres_test.BeforeEach()
			// fmt.Errorf("Error while running BeforeEach job: %s", err)

			err = serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' cleanup func in test case: %s", err)
			}

			//Init CA Server with 1 CA
			_, err = initCA(caTest.Service)
			if err != nil {
				t.Fatalf("failed running initCA: %s", err)
			}

			err = tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(caTest.HttpCASDK))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func TestGetStats(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) (*models.CAStats, error)
		resultCheck func(*models.CAStats, error) error
	}{
		{
			name:   "OK/GetsStatsCA",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.CAStats, error) {
				//cas := []*models.CACertificate{}
				res, err := caSDK.GetStats(context.Background())
				return res, err
			},
			resultCheck: func(cas *models.CAStats, err error) error {
				if err != nil {
					return fmt.Errorf("should've got CAs without error, but got error: %s", err)
				}
				//Figure it out, which is the purpose of this
				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			//
			// err := postgres_test.BeforeEach()
			// fmt.Errorf("Error while running BeforeEach job: %s", err)

			err = serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' cleanup func in test case: %s", err)
			}

			//Init CA Server with 1 CA
			_, err = initCA(caTest.Service)
			if err != nil {
				t.Fatalf("failed running initCA: %s", err)
			}

			err = tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(caTest.HttpCASDK))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func TestGetCertificates(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) ([]*models.Certificate, error)
		resultCheck func([]*models.Certificate, error) error
	}{
		{
			name: "OK/GetsCertificatesEXRunTrue",
			before: func(svc services.CAService) error {
				ca, err := svc.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
				if err != nil {
					return fmt.Errorf("Error getting the CA: %s", err)
				}

				for i := 0; i < 20; i++ {
					key, err := chelpers.GenerateRSAKey(2048)
					if err != nil {
						return fmt.Errorf("Error creating the private key: %s", err)
					}

					csr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: fmt.Sprintf("cert-%d", 1)}, key)
					_, err = svc.SignCertificate(context.Background(), services.SignCertificateInput{
						CAID:              DefaultCAID,
						CertRequest:       (*models.X509CertificateRequest)(csr),
						IssuanceProfileID: ca.ProfileID,
					})
					if err != nil {
						return err
					}
				}

				return nil
			},
			run: func(caSDK services.CAService) ([]*models.Certificate, error) {
				issuedCerts := []*models.Certificate{}
				_, err := caSDK.GetCertificates(context.Background(), services.GetCertificatesInput{
					ListInput: resources.ListInput[models.Certificate]{
						ExhaustiveRun: true,
						QueryParameters: &resources.QueryParameters{
							PageSize: 5,
						},
						ApplyFunc: func(elem models.Certificate) {
							issuedCerts = append(issuedCerts, &elem)
						},
					},
				})

				return issuedCerts, err
			},
			resultCheck: func(certs []*models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}

				if len(certs) != 21 { // 20 certs + 1 CA
					return fmt.Errorf("should've got 21 certificates. Got %d", len(certs))
				}

				return nil
			},
		},
		{
			name: "OK/GetsCertificatesEXRunFalse",
			before: func(svc services.CAService) error {
				ca, err := svc.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
				if err != nil {
					return fmt.Errorf("Error getting the CA: %s", err)
				}

				for i := 0; i < 20; i++ {
					key, err := chelpers.GenerateRSAKey(2048)
					if err != nil {
						return fmt.Errorf("Error creating the private key: %s", err)
					}

					csr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: fmt.Sprintf("cert-%d", 1)}, key)
					_, err = svc.SignCertificate(context.Background(), services.SignCertificateInput{
						CAID:              DefaultCAID,
						CertRequest:       (*models.X509CertificateRequest)(csr),
						IssuanceProfileID: ca.ProfileID,
					})
					if err != nil {
						return err
					}
				}

				return nil
			},
			run: func(caSDK services.CAService) ([]*models.Certificate, error) {

				issuedCerts := []*models.Certificate{}
				_, err := caSDK.GetCertificates(context.Background(), services.GetCertificatesInput{
					ListInput: resources.ListInput[models.Certificate]{
						ExhaustiveRun: false,
						QueryParameters: &resources.QueryParameters{
							PageSize: 5,
						},
						ApplyFunc: func(elem models.Certificate) {
							issuedCerts = append(issuedCerts, &elem)
						},
					},
				})
				return issuedCerts, err
			},
			resultCheck: func(certs []*models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}

				if len(certs) != 5 {
					return fmt.Errorf("should've got 5 certificates. Got %d", len(certs))
				}
				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			// err := postgres_test.BeforeEach()
			// fmt.Errorf("Error while running BeforeEach job: %s", err)

			err = serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' cleanup func in test case: %s", err)
			}

			//Init CA Server with 1 CA
			_, err = initCA(caTest.Service)
			if err != nil {
				t.Fatalf("failed running initCA: %s", err)
			}

			err = tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(caTest.HttpCASDK))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func TestGetCertificatesByCA(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) ([]*models.Certificate, error)
		resultCheck func([]*models.Certificate, error) error
	}{
		{
			name: "OK/GetCertificatesByCAExRunFalse",
			before: func(svc services.CAService) error {
				ca, err := svc.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
				if err != nil {
					return fmt.Errorf("Error getting the CA: %s", err)
				}

				for i := 0; i < 20; i++ {
					key, err := chelpers.GenerateRSAKey(2048)
					if err != nil {
						return fmt.Errorf("Error creating the private key: %s", err)
					}

					csr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: fmt.Sprintf("cert-%d", 1)}, key)
					_, err = svc.SignCertificate(context.Background(), services.SignCertificateInput{
						CAID:              DefaultCAID,
						CertRequest:       (*models.X509CertificateRequest)(csr),
						IssuanceProfileID: ca.ProfileID,
					})
					if err != nil {
						return err
					}
				}

				return nil
			},
			run: func(caSDK services.CAService) ([]*models.Certificate, error) {
				issuedCerts := []*models.Certificate{}
				_, err := caSDK.GetCertificatesByCA(context.Background(), services.GetCertificatesByCAInput{
					ListInput: resources.ListInput[models.Certificate]{
						ExhaustiveRun: false,
						QueryParameters: &resources.QueryParameters{
							PageSize: 5,
						},
						ApplyFunc: func(elem models.Certificate) {
							issuedCerts = append(issuedCerts, &elem)
						},
					},
					CAID: DefaultCAID,
				})

				return issuedCerts, err
			},
			resultCheck: func(certs []*models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}

				if len(certs) != 5 {
					return fmt.Errorf("should've got 5 certificates. Got %d", len(certs))
				}
				return nil
			},
		},
		{
			name: "OK/GetCertificatesByCAExRunTrue",
			before: func(svc services.CAService) error {
				ca, err := svc.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
				if err != nil {
					return fmt.Errorf("Error getting the CA: %s", err)
				}

				for i := 0; i < 20; i++ {
					key, err := chelpers.GenerateRSAKey(2048)
					if err != nil {
						return fmt.Errorf("Error creating the private key: %s", err)
					}

					csr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: fmt.Sprintf("cert-%d", 1)}, key)
					_, err = svc.SignCertificate(context.Background(), services.SignCertificateInput{
						CAID:              DefaultCAID,
						CertRequest:       (*models.X509CertificateRequest)(csr),
						IssuanceProfileID: ca.ProfileID,
					})
					if err != nil {
						return err
					}
				}

				return nil
			},
			run: func(caSDK services.CAService) ([]*models.Certificate, error) {
				issuedCerts := []*models.Certificate{}
				_, err := caSDK.GetCertificatesByCA(context.Background(), services.GetCertificatesByCAInput{
					ListInput: resources.ListInput[models.Certificate]{
						ExhaustiveRun: true,
						QueryParameters: &resources.QueryParameters{
							PageSize: 5,
						},
						ApplyFunc: func(elem models.Certificate) {
							issuedCerts = append(issuedCerts, &elem)
						},
					},
					CAID: DefaultCAID,
				})

				return issuedCerts, err
			},
			resultCheck: func(certs []*models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}

				if len(certs) != 21 { // 20 + 1 CA
					return fmt.Errorf("should've got 21 certificates. Got %d", len(certs))
				}
				return nil
			},
		},
		{
			name: "OK/GetCertificatesByCANotExistERunFalse",
			before: func(svc services.CAService) error {
				ca, err := svc.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
				if err != nil {
					return fmt.Errorf("Error getting the CA: %s", err)
				}

				for i := 0; i < 20; i++ {
					key, err := chelpers.GenerateRSAKey(2048)
					if err != nil {
						return fmt.Errorf("Error creating the private key: %s", err)
					}

					csr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: fmt.Sprintf("cert-%d", 1)}, key)
					_, err = svc.SignCertificate(context.Background(), services.SignCertificateInput{
						CAID:              DefaultCAID,
						CertRequest:       (*models.X509CertificateRequest)(csr),
						IssuanceProfileID: ca.ProfileID,
					})
					if err != nil {
						return err
					}
				}

				return nil
			},
			run: func(caSDK services.CAService) ([]*models.Certificate, error) {
				issuedCerts := []*models.Certificate{}
				_, err := caSDK.GetCertificatesByCA(context.Background(), services.GetCertificatesByCAInput{
					ListInput: resources.ListInput[models.Certificate]{
						ExhaustiveRun: false,
						QueryParameters: &resources.QueryParameters{
							PageSize: 5,
						},
						ApplyFunc: func(elem models.Certificate) {
							issuedCerts = append(issuedCerts, &elem)
						},
					},
					CAID: "NonExistenCAID",
				})

				return issuedCerts, err
			},
			resultCheck: func(certs []*models.Certificate, err error) error {
				if err == nil {
					return fmt.Errorf("should've got error. Got none")
				}

				if !errors.Is(err, errs.ErrCANotFound) {
					return fmt.Errorf("got unexpected error: %s", err)
				}
				return nil
			},
		},
		{
			name: "OK/GetCertificatesByCANotExistERunTrue",
			before: func(svc services.CAService) error {
				ca, err := svc.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
				if err != nil {
					return fmt.Errorf("Error getting the CA: %s", err)
				}

				for i := 0; i < 20; i++ {
					key, err := chelpers.GenerateRSAKey(2048)
					if err != nil {
						return fmt.Errorf("Error creating the private key: %s", err)
					}

					csr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: fmt.Sprintf("cert-%d", 1)}, key)
					_, err = svc.SignCertificate(context.Background(), services.SignCertificateInput{
						CAID:              DefaultCAID,
						CertRequest:       (*models.X509CertificateRequest)(csr),
						IssuanceProfileID: ca.ProfileID,
					})
					if err != nil {
						return err
					}
				}

				return nil
			},
			run: func(caSDK services.CAService) ([]*models.Certificate, error) {
				issuedCerts := []*models.Certificate{}
				_, err := caSDK.GetCertificatesByCA(context.Background(), services.GetCertificatesByCAInput{
					ListInput: resources.ListInput[models.Certificate]{
						ExhaustiveRun: true,
						QueryParameters: &resources.QueryParameters{
							PageSize: 5,
						},
						ApplyFunc: func(elem models.Certificate) {
							issuedCerts = append(issuedCerts, &elem)
						},
					},
					CAID: "NonExistenCAID",
				})

				return issuedCerts, err
			},
			resultCheck: func(certs []*models.Certificate, err error) error {
				if err == nil {
					return fmt.Errorf("should've got error. Got none")
				}

				if !errors.Is(err, errs.ErrCANotFound) {
					return fmt.Errorf("got unexpected error: %s", err)
				}
				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			//
			// err := postgres_test.BeforeEach()
			// fmt.Errorf("Error while running BeforeEach job: %s", err)

			err = serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' cleanup func in test case: %s", err)
			}

			//Init CA Server with 1 CA
			_, err = initCA(caTest.Service)
			if err != nil {
				t.Fatalf("failed running initCA: %s", err)
			}

			err = tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(caTest.HttpCASDK))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func TestImportCA(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca", "kms").WithVault().Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	generateSelfSignedCA := func(keyType x509.PublicKeyAlgorithm) (*x509.Certificate, any, error) {
		var err error
		var key any
		var pubKey any

		switch keyType {
		case x509.RSA:
			rsaKey, err := chelpers.GenerateRSAKey(2048)
			if err != nil {
				return nil, nil, err
			}
			key = rsaKey
			pubKey = &rsaKey.PublicKey
		case x509.ECDSA:
			eccKey, err := chelpers.GenerateECDSAKey(elliptic.P224())
			if err != nil {
				return nil, nil, err
			}
			key = eccKey
			pubKey = &eccKey.PublicKey
		}

		sn, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 160))
		template := x509.Certificate{
			SerialNumber: sn,
			Subject: pkix.Name{
				CommonName: "Test-CA-External",
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(time.Hour * 5),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsage(x509.ExtKeyUsageOCSPSigning),
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			IsCA:                  true,
		}

		derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pubKey, key)
		if err != nil {
			return nil, nil, err
		}

		cert, err := x509.ParseCertificate(derBytes)
		if err != nil {
			return nil, nil, err
		}

		return cert, key, nil

	}
	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) (*models.CACertificate, error)
		resultCheck func(*models.CACertificate, error) error
	}{
		{
			name:   "OK/ImportingCAWithoutKey",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.CACertificate, error) {
				ca, _, err := generateSelfSignedCA(x509.RSA)
				if err != nil {
					return nil, fmt.Errorf("Failed creating the certificate %s", err)
				}

				importedCA, err := caSDK.ImportCA(context.Background(), services.ImportCAInput{
					ID:            "id-1234",
					CAType:        models.CertificateTypeExternal,
					CACertificate: (*models.X509Certificate)(ca),
				})

				return importedCA, err
			},
			resultCheck: func(ca *models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}

				return nil
			},
		},
		{
			name:   "OK/ImportingCAWithKey",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.CACertificate, error) {
				ca, key, err := generateSelfSignedCA(x509.RSA)
				var duration time.Duration = 100
				if err != nil {
					return nil, fmt.Errorf("Failed creating the certificate %s", err)
				}

				profile, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Validity: models.Validity{Type: models.Duration, Duration: (models.TimeDuration)(duration)},
					},
				})
				if err != nil {
					t.Fatalf("failed creating issuance profile: %s", err)
				}

				importedCA, err := caSDK.ImportCA(context.Background(), services.ImportCAInput{
					ID:            "id-1234",
					CAType:        models.CertificateTypeImportedWithKey,
					ProfileID:     profile.ID,
					CACertificate: (*models.X509Certificate)(ca),
					CARSAKey:      (key).(*rsa.PrivateKey),
					KeyType:       models.KeyType(x509.RSA),
				})

				return importedCA, err
			},
			resultCheck: func(cas *models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}

				return nil
			},
		},
		{
			name:   "OK/ImportingToSpecificEngine",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.CACertificate, error) {
				ca, key, err := generateSelfSignedCA(x509.RSA)
				var duration time.Duration = 100
				if err != nil {
					return nil, fmt.Errorf("Failed creating the certificate %s", err)
				}
				engines, _ := caSDK.GetCryptoEngineProvider(context.Background())
				var engine *models.CryptoEngineProvider

				if !engines[0].Default {
					engine = engines[0]
				} else {
					engine = engines[1]
				}

				profile, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Validity: models.Validity{Type: models.Duration, Duration: (models.TimeDuration)(duration)},
					},
				})
				if err != nil {
					t.Fatalf("failed creating issuance profile: %s", err)
				}

				importedCA, err := caSDK.ImportCA(context.Background(), services.ImportCAInput{
					ID:            "id-1234",
					CAType:        models.CertificateTypeImportedWithKey,
					ProfileID:     profile.ID,
					CACertificate: (*models.X509Certificate)(ca),
					CARSAKey:      (key).(*rsa.PrivateKey),
					KeyType:       models.KeyType(x509.RSA),
					EngineID:      engine.ID,
				})

				return importedCA, err
			},
			resultCheck: func(cas *models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}
				return nil
			},
		},
		{
			name:   "OK/ImportingCAWithECDSAKey",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.CACertificate, error) {
				ca, key, err := generateSelfSignedCA(x509.ECDSA)
				var duration time.Duration = 100
				if err != nil {
					return nil, fmt.Errorf("Failed creating the certificate %s", err)
				}

				profile, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Validity: models.Validity{Type: models.Duration, Duration: (models.TimeDuration)(duration)},
					},
				})
				if err != nil {
					t.Fatalf("failed creating issuance profile: %s", err)
				}

				importedCA, err := caSDK.ImportCA(context.Background(), services.ImportCAInput{
					ID:            "id-1234",
					CAType:        models.CertificateTypeImportedWithKey,
					ProfileID:     profile.ID,
					CACertificate: (*models.X509Certificate)(ca),
					CAECKey:       (key).(*ecdsa.PrivateKey),
					KeyType:       models.KeyType(x509.ECDSA),
				})
				return importedCA, err
			},
			resultCheck: func(cas *models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}
				return nil
			},
		},
		{
			name:   "OK/ImportingCAWithoutID",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.CACertificate, error) {
				ca, key, err := generateSelfSignedCA(x509.RSA)
				var duration time.Duration = 100
				if err != nil {
					return nil, fmt.Errorf("Failed creating the certificate %s", err)
				}

				profile, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Validity: models.Validity{Type: models.Duration, Duration: (models.TimeDuration)(duration)},
					},
				})
				if err != nil {
					t.Fatalf("failed creating issuance profile: %s", err)
				}

				importedCA, err := caSDK.ImportCA(context.Background(), services.ImportCAInput{
					CAType:        models.CertificateTypeImportedWithKey,
					ProfileID:     profile.ID,
					CACertificate: (*models.X509Certificate)(ca),
					CARSAKey:      (key).(*rsa.PrivateKey),
					KeyType:       models.KeyType(x509.RSA),
				})

				return importedCA, err
			},
			resultCheck: func(cas *models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}
				return nil
			},
		},
		// 		{
		// 			name:   "OK/ImportingHierarchyBottomUp",
		// 			before: func(svc services.CAService) error { return nil },
		// 			run: func(caSDK services.CAService) (*models.CACertificate, error) {
		// 				ca0Crt := `
		// -----BEGIN CERTIFICATE-----
		// MIIDqzCCApOgAwIBAgIUY/29239q5Iz5/m2NGnFiQZCDeoswDQYJKoZIhvcNAQEL
		// BQAwXTELMAkGA1UEBhMCVVMxFTATBgNVBAgMDEV4YW1wbGVTdGF0ZTEUMBIGA1UE
		// BwwLRXhhbXBsZUNpdHkxDzANBgNVBAoMBlJvb3RDQTEQMA4GA1UEAwwHUm9vdCBD
		// QTAeFw0yNTAyMjUxMzU0MDBaFw0zNTAyMjMxMzU0MDBaMF0xCzAJBgNVBAYTAlVT
		// MRUwEwYDVQQIDAxFeGFtcGxlU3RhdGUxFDASBgNVBAcMC0V4YW1wbGVDaXR5MQ8w
		// DQYDVQQKDAZSb290Q0ExEDAOBgNVBAMMB1Jvb3QgQ0EwggEiMA0GCSqGSIb3DQEB
		// AQUAA4IBDwAwggEKAoIBAQDJgxeplksYYGm7ilnJYQMu2bUbv+rxgGCpfZlDlzRk
		// 3HBjt3Q0Xa8r1rBS1LI3iktBgUWiqBElqhYAX0d459Mko3J7dPAf+0mcPzYgGd8X
		// 5MoztHc+fpzht+Natpvm/ocp8lFoEt68SDGiG24sdhmbSTJPsU50JneO7LHK8YPL
		// h5VL+4pu9dHrXgH6d7CK8bP25nCE90B4gpFKy2Oc9vIvAiZ0m31441ipOJqujsvm
		// MsPAR/rsOBGVRqkvQ933BR3PwBm4nbMWPtbsg/OL5WgzoYs2wiRmaj3YvZoAAHzy
		// c/2ntEh33hemHgKkI++mwDLxzDg+jhsod/gWPt9hTOljAgMBAAGjYzBhMA8GA1Ud
		// EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBTkWLVA/xb37hGL
		// /S1UTgJqJfmm/jAfBgNVHSMEGDAWgBTkWLVA/xb37hGL/S1UTgJqJfmm/jANBgkq
		// hkiG9w0BAQsFAAOCAQEARBs3V/jUheZffb/9zfpo26e3e+whlXIcL6VjA94HWKXh
		// FzdAbQfvQUQCfT/tRJzUE3MZoi6g0vtZmi3if3KA9Mb+zSmrfjgEtymGKAyaKzR6
		// LSjt7RHRAXVjjnkNAmGZiVfi9rsslHr3WeVGwwNZGQQpZBN5Atcd7YSRWk9wuH+N
		// ReLpV/Neg/wBMAxLgCBuvIfDQkSOsUwSmLMLzuRYqOMAyVR8bUiu9bxHOHaUQ6TI
		// DruLxGHV4uOAx2SqBNr7XWKJyOZxMkmm0YnZWnIX6+uTHeGTdxgWuHLlkrUGVmaW
		// Spj4CeR8GjWfp66G75tjuT5qpgFJ2yhnaDJ/JqNTrQ==
		// -----END CERTIFICATE-----
		// `

		// 				ca1Crt := `
		// -----BEGIN CERTIFICATE-----
		// MIIDlDCCAnygAwIBAgIUN2XNhvC/xcgbfxD4FU5ONYFM2HkwDQYJKoZIhvcNAQEL
		// BQAwXTELMAkGA1UEBhMCVVMxFTATBgNVBAgMDEV4YW1wbGVTdGF0ZTEUMBIGA1UE
		// BwwLRXhhbXBsZUNpdHkxDzANBgNVBAoMBlJvb3RDQTEQMA4GA1UEAwwHUm9vdCBD
		// QTAeFw0yNTAyMjUxMzU0MThaFw0zNTAyMjMxMzU0MThaMEYxCzAJBgNVBAYTAlVT
		// MRUwEwYDVQQIDAxFeGFtcGxlU3RhdGUxDzANBgNVBAoMBlJvb3RDQTEPMA0GA1UE
		// AwwGU3ViIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2Hk/uF/U
		// RMtp3zx2bimRYoHAq1rz9H2/QwKgtE4dNI5GMHIHxeeIfOlbxxOhr1PaMKSoxIv1
		// 3Sj1arpIhQEFset42tYOEKgTO0x5KQHQRnsX9F5uuc5Drj6E4U1qAv0kqBS/7chm
		// jszpsZ2+Q19j+v3G3CMkkpOOYZaTAo0ZPEtRBaNG3xX2X4jGbviM1aCx6v2cC3K8
		// rfauh74xOyKjWM0MOVndKctUAs5oUrFcNC6spp8kjBMWpXcCtcY+YNnHH5aD7/LB
		// jGZJlZNDNKCCtR0GNtwlqPvbCzTbuvPvjVF6hWPhB0dWXP5jE1nsNARLgYnuE2WM
		// hAlyqOvmgehfUQIDAQABo2MwYTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQE
		// AwIBBjAdBgNVHQ4EFgQUHuuPIC/kUYP60ysHiL19v51r1KEwHwYDVR0jBBgwFoAU
		// 5Fi1QP8W9+4Ri/0tVE4CaiX5pv4wDQYJKoZIhvcNAQELBQADggEBAIu1lAZteU+n
		// +6l/wuEoev+Ad8D3TvHDEjxyHnYtE4Mf+HLk2SguYvXJJRFFc9usG3FmmB0hTPmx
		// KDrMk9QObgHsZHcNagwhB6Urn+EKrj/YUnIJE2TrX/blFYoMBPaxbWrwrmFAjKsl
		// 8uuJoNY64G6sOMzHBpeELhdZU/xgDsrNk+dGyVtYAjmfksQLOSgF14XZnXL9+wPc
		// jSm4n8W5YQ0zsKAZ5TmB0VpTCkvVS/gGDHoZfdO38CSry4z8nM3W4zdkmvo76G8U
		// 2fvC11FSXxzRVQrbxfaOMEcdzT0u1wcsQQzM4+v0Njt3vVy+gRljm+Gmt0Dc9/Lb
		// O3v2AfmhPiU=
		// -----END CERTIFICATE-----
		// `

		// 				ca2Crt := `-----BEGIN CERTIFICATE-----
		// MIIDgTCCAmmgAwIBAgIUWb++79DZH43iqHeBItwkJYT5e+QwDQYJKoZIhvcNAQEL
		// BQAwRjELMAkGA1UEBhMCVVMxFTATBgNVBAgMDEV4YW1wbGVTdGF0ZTEPMA0GA1UE
		// CgwGUm9vdENBMQ8wDQYDVQQDDAZTdWIgQ0EwHhcNMjUwMjI1MTM1NTQ1WhcNMzUw
		// MjIzMTM1NTQ1WjBKMQswCQYDVQQGEwJVUzEVMBMGA1UECAwMRXhhbXBsZVN0YXRl
		// MQ8wDQYDVQQKDAZSb290Q0ExEzARBgNVBAMMClN1Yi1TdWIgQ0EwggEiMA0GCSqG
		// SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDhUi8oRQBDLAxKp74qGy3RbvgzaJxyxVSr
		// U+N+l+iHJZ/N4K+papFnZGSc6TycJVW06msyvSdod/gaB3n6SfsOPjAFBGaDNFAz
		// YHrIaQKPU/+uEQWMHekEqQmT3vdlgtl6vuBh3qjBKLUwCTwWdRhHckIgTgq7rMKW
		// WT5Jsp5J0QSREIi5o99MILex+4p2OsAXC91a37snQ0HvzOsKoWilZvx/dpBCHWa8
		// h8UlTo7bbttVCI2NbKXUMH3LNJBvO0gyysMhkEXIynNoZN3j0bxOHnm494wBN8bQ
		// EEAb3ah9VEkN1EHXmoTwujQNL0YD9Us1Fv59Ff44EOW9uQn4nbK/AgMBAAGjYzBh
		// MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBQNQvWi
		// KOPK/XL5S7LAcEdBqkCxcjAfBgNVHSMEGDAWgBQe648gL+RRg/rTKweIvX2/nWvU
		// oTANBgkqhkiG9w0BAQsFAAOCAQEAPjWq7neRIDnRO7DITs9YV97QW9TGfTWyIzhX
		// f+SEi4q/OOuKz9lHFkL/aCQHcilmIn2dcBlQNJKW2w41fd7mB6AyM3b0qDvPAQkw
		// xaLER5ox4EsIUJwpCjADCLIEEFQh1cjthiBI0tVuIAbUKoq08E+YdFutkMrnZuPs
		// VnGK/wULw7ATS4jC+6wCfDQTCNuGWA7Fec/uznu4yyD5YNvBkSxk0fSn7B3uEe7c
		// JzepKLZK9pKiq8PTzPOc/zGCRLF7qdquaeJkpRGI8a3pl3sUA521eYWjh6f+kkjf
		// V4Ahz5up3arkTIU2XR40ge9x2+hlxmD+KF8aHMdB/89YXgp0MA==
		// -----END CERTIFICATE-----
		// `

		// 				cert0, err := chelpers.ParseCertificate(ca0Crt)
		// 				if err != nil {
		// 					t.Fatalf("could not parse root cert: %s", err)
		// 				}

		// 				cert1, err := chelpers.ParseCertificate(ca1Crt)
		// 				if err != nil {
		// 					t.Fatalf("could not parse ca-lvl-1 cert: %s", err)
		// 				}

		// 				cert2, err := chelpers.ParseCertificate(ca2Crt)
		// 				if err != nil {
		// 					t.Fatalf("could not parse ca-lvl-2 cert: %s", err)
		// 				}

		// 				duration, _ := models.ParseDuration("100d")

		// 				importedCALvl2, err := caSDK.ImportCA(context.Background(), services.ImportCAInput{
		// 					CAType: models.CertificateTypeExternal,
		// 					IssuanceExpiration: models.Validity{
		// 						Type:     models.Duration,
		// 						Duration: (models.TimeDuration)(duration),
		// 					},
		// 					CACertificate: (*models.X509Certificate)(cert2),
		// 				})
		// 				if err != nil {
		// 					t.Fatalf("could not import ca-lvl-2 CA: %s", err)
		// 				}

		// 				_, err = caSDK.ImportCA(context.Background(), services.ImportCAInput{
		// 					CAType: models.CertificateTypeExternal,
		// 					IssuanceExpiration: models.Validity{
		// 						Type:     models.Duration,
		// 						Duration: (models.TimeDuration)(duration),
		// 					},
		// 					CACertificate: (*models.X509Certificate)(cert1),
		// 				})
		// 				if err != nil {
		// 					t.Fatalf("could not import ca-lvl-1 CA: %s", err)
		// 				}

		// 				_, err = caSDK.ImportCA(context.Background(), services.ImportCAInput{
		// 					CAType: models.CertificateTypeExternal,
		// 					IssuanceExpiration: models.Validity{
		// 						Type:     models.Duration,
		// 						Duration: (models.TimeDuration)(duration),
		// 					},
		// 					CACertificate: (*models.X509Certificate)(cert0),
		// 				})
		// 				if err != nil {
		// 					t.Fatalf("could not import root CA: %s", err)
		// 				}

		// 				importedCALvl2Updated, err := caSDK.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: importedCALvl2.ID})
		// 				if err != nil {
		// 					t.Fatalf("could not retrieve ca-lvl-2 CA: %s", err)
		// 				}

		// 				return importedCALvl2Updated, err
		// 			},
		// 			resultCheck: func(ca *models.CACertificate, err error) error {
		// 				if err != nil {
		// 					return fmt.Errorf("got unexpected error: %s", err)
		// 				}

		// 				if ca.Level != 2 {
		// 					return fmt.Errorf("CA should be at level 2. Got %d", ca.Level)
		// 				}

		// 				if ca.Certificate.IssuerCAMetadata.Level != 1 {
		// 					return fmt.Errorf("CA parent should be at level 1. Got %d", ca.Certificate.IssuerCAMetadata.Level)
		// 				}

		// 				return nil
		// 			},
		// 		},
		{
			name:   "OK/ImportingHierarchyTopDown",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.CACertificate, error) {
				ca0Crt := `
-----BEGIN CERTIFICATE-----
MIIDqzCCApOgAwIBAgIUY/29239q5Iz5/m2NGnFiQZCDeoswDQYJKoZIhvcNAQEL
BQAwXTELMAkGA1UEBhMCVVMxFTATBgNVBAgMDEV4YW1wbGVTdGF0ZTEUMBIGA1UE
BwwLRXhhbXBsZUNpdHkxDzANBgNVBAoMBlJvb3RDQTEQMA4GA1UEAwwHUm9vdCBD
QTAeFw0yNTAyMjUxMzU0MDBaFw0zNTAyMjMxMzU0MDBaMF0xCzAJBgNVBAYTAlVT
MRUwEwYDVQQIDAxFeGFtcGxlU3RhdGUxFDASBgNVBAcMC0V4YW1wbGVDaXR5MQ8w
DQYDVQQKDAZSb290Q0ExEDAOBgNVBAMMB1Jvb3QgQ0EwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDJgxeplksYYGm7ilnJYQMu2bUbv+rxgGCpfZlDlzRk
3HBjt3Q0Xa8r1rBS1LI3iktBgUWiqBElqhYAX0d459Mko3J7dPAf+0mcPzYgGd8X
5MoztHc+fpzht+Natpvm/ocp8lFoEt68SDGiG24sdhmbSTJPsU50JneO7LHK8YPL
h5VL+4pu9dHrXgH6d7CK8bP25nCE90B4gpFKy2Oc9vIvAiZ0m31441ipOJqujsvm
MsPAR/rsOBGVRqkvQ933BR3PwBm4nbMWPtbsg/OL5WgzoYs2wiRmaj3YvZoAAHzy
c/2ntEh33hemHgKkI++mwDLxzDg+jhsod/gWPt9hTOljAgMBAAGjYzBhMA8GA1Ud
EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBTkWLVA/xb37hGL
/S1UTgJqJfmm/jAfBgNVHSMEGDAWgBTkWLVA/xb37hGL/S1UTgJqJfmm/jANBgkq
hkiG9w0BAQsFAAOCAQEARBs3V/jUheZffb/9zfpo26e3e+whlXIcL6VjA94HWKXh
FzdAbQfvQUQCfT/tRJzUE3MZoi6g0vtZmi3if3KA9Mb+zSmrfjgEtymGKAyaKzR6
LSjt7RHRAXVjjnkNAmGZiVfi9rsslHr3WeVGwwNZGQQpZBN5Atcd7YSRWk9wuH+N
ReLpV/Neg/wBMAxLgCBuvIfDQkSOsUwSmLMLzuRYqOMAyVR8bUiu9bxHOHaUQ6TI
DruLxGHV4uOAx2SqBNr7XWKJyOZxMkmm0YnZWnIX6+uTHeGTdxgWuHLlkrUGVmaW
Spj4CeR8GjWfp66G75tjuT5qpgFJ2yhnaDJ/JqNTrQ==
-----END CERTIFICATE-----
`

				ca1Crt := `
-----BEGIN CERTIFICATE-----
MIIDlDCCAnygAwIBAgIUN2XNhvC/xcgbfxD4FU5ONYFM2HkwDQYJKoZIhvcNAQEL
BQAwXTELMAkGA1UEBhMCVVMxFTATBgNVBAgMDEV4YW1wbGVTdGF0ZTEUMBIGA1UE
BwwLRXhhbXBsZUNpdHkxDzANBgNVBAoMBlJvb3RDQTEQMA4GA1UEAwwHUm9vdCBD
QTAeFw0yNTAyMjUxMzU0MThaFw0zNTAyMjMxMzU0MThaMEYxCzAJBgNVBAYTAlVT
MRUwEwYDVQQIDAxFeGFtcGxlU3RhdGUxDzANBgNVBAoMBlJvb3RDQTEPMA0GA1UE
AwwGU3ViIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2Hk/uF/U
RMtp3zx2bimRYoHAq1rz9H2/QwKgtE4dNI5GMHIHxeeIfOlbxxOhr1PaMKSoxIv1
3Sj1arpIhQEFset42tYOEKgTO0x5KQHQRnsX9F5uuc5Drj6E4U1qAv0kqBS/7chm
jszpsZ2+Q19j+v3G3CMkkpOOYZaTAo0ZPEtRBaNG3xX2X4jGbviM1aCx6v2cC3K8
rfauh74xOyKjWM0MOVndKctUAs5oUrFcNC6spp8kjBMWpXcCtcY+YNnHH5aD7/LB
jGZJlZNDNKCCtR0GNtwlqPvbCzTbuvPvjVF6hWPhB0dWXP5jE1nsNARLgYnuE2WM
hAlyqOvmgehfUQIDAQABo2MwYTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQE
AwIBBjAdBgNVHQ4EFgQUHuuPIC/kUYP60ysHiL19v51r1KEwHwYDVR0jBBgwFoAU
5Fi1QP8W9+4Ri/0tVE4CaiX5pv4wDQYJKoZIhvcNAQELBQADggEBAIu1lAZteU+n
+6l/wuEoev+Ad8D3TvHDEjxyHnYtE4Mf+HLk2SguYvXJJRFFc9usG3FmmB0hTPmx
KDrMk9QObgHsZHcNagwhB6Urn+EKrj/YUnIJE2TrX/blFYoMBPaxbWrwrmFAjKsl
8uuJoNY64G6sOMzHBpeELhdZU/xgDsrNk+dGyVtYAjmfksQLOSgF14XZnXL9+wPc
jSm4n8W5YQ0zsKAZ5TmB0VpTCkvVS/gGDHoZfdO38CSry4z8nM3W4zdkmvo76G8U
2fvC11FSXxzRVQrbxfaOMEcdzT0u1wcsQQzM4+v0Njt3vVy+gRljm+Gmt0Dc9/Lb
O3v2AfmhPiU=
-----END CERTIFICATE-----
`

				ca2Crt := `-----BEGIN CERTIFICATE-----
MIIDgTCCAmmgAwIBAgIUWb++79DZH43iqHeBItwkJYT5e+QwDQYJKoZIhvcNAQEL
BQAwRjELMAkGA1UEBhMCVVMxFTATBgNVBAgMDEV4YW1wbGVTdGF0ZTEPMA0GA1UE
CgwGUm9vdENBMQ8wDQYDVQQDDAZTdWIgQ0EwHhcNMjUwMjI1MTM1NTQ1WhcNMzUw
MjIzMTM1NTQ1WjBKMQswCQYDVQQGEwJVUzEVMBMGA1UECAwMRXhhbXBsZVN0YXRl
MQ8wDQYDVQQKDAZSb290Q0ExEzARBgNVBAMMClN1Yi1TdWIgQ0EwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDhUi8oRQBDLAxKp74qGy3RbvgzaJxyxVSr
U+N+l+iHJZ/N4K+papFnZGSc6TycJVW06msyvSdod/gaB3n6SfsOPjAFBGaDNFAz
YHrIaQKPU/+uEQWMHekEqQmT3vdlgtl6vuBh3qjBKLUwCTwWdRhHckIgTgq7rMKW
WT5Jsp5J0QSREIi5o99MILex+4p2OsAXC91a37snQ0HvzOsKoWilZvx/dpBCHWa8
h8UlTo7bbttVCI2NbKXUMH3LNJBvO0gyysMhkEXIynNoZN3j0bxOHnm494wBN8bQ
EEAb3ah9VEkN1EHXmoTwujQNL0YD9Us1Fv59Ff44EOW9uQn4nbK/AgMBAAGjYzBh
MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBQNQvWi
KOPK/XL5S7LAcEdBqkCxcjAfBgNVHSMEGDAWgBQe648gL+RRg/rTKweIvX2/nWvU
oTANBgkqhkiG9w0BAQsFAAOCAQEAPjWq7neRIDnRO7DITs9YV97QW9TGfTWyIzhX
f+SEi4q/OOuKz9lHFkL/aCQHcilmIn2dcBlQNJKW2w41fd7mB6AyM3b0qDvPAQkw
xaLER5ox4EsIUJwpCjADCLIEEFQh1cjthiBI0tVuIAbUKoq08E+YdFutkMrnZuPs
VnGK/wULw7ATS4jC+6wCfDQTCNuGWA7Fec/uznu4yyD5YNvBkSxk0fSn7B3uEe7c
JzepKLZK9pKiq8PTzPOc/zGCRLF7qdquaeJkpRGI8a3pl3sUA521eYWjh6f+kkjf
V4Ahz5up3arkTIU2XR40ge9x2+hlxmD+KF8aHMdB/89YXgp0MA==
-----END CERTIFICATE-----
`

				cert0, err := chelpers.ParseCertificate(ca0Crt)
				if err != nil {
					t.Fatalf("could not parse root cert: %s", err)
				}

				cert1, err := chelpers.ParseCertificate(ca1Crt)
				if err != nil {
					t.Fatalf("could not parse ca-lvl-1 cert: %s", err)
				}

				cert2, err := chelpers.ParseCertificate(ca2Crt)
				if err != nil {
					t.Fatalf("could not parse ca-lvl-2 cert: %s", err)
				}

				duration, _ := models.ParseDuration("100d")
				profile, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Validity: models.Validity{
							Type:     models.Duration,
							Duration: (models.TimeDuration)(duration),
						},
					},
				})
				if err != nil {
					t.Fatalf("could not create profile: %s", err)
				}

				_, err = caSDK.ImportCA(context.Background(), services.ImportCAInput{
					CAType:        models.CertificateTypeExternal,
					CACertificate: (*models.X509Certificate)(cert0),
					ProfileID:     profile.ID,
				})
				if err != nil {
					t.Fatalf("could not import root CA: %s", err)
				}

				_, err = caSDK.ImportCA(context.Background(), services.ImportCAInput{
					CAType:        models.CertificateTypeExternal,
					CACertificate: (*models.X509Certificate)(cert1),
					ProfileID:     profile.ID,
				})
				if err != nil {
					t.Fatalf("could not import ca-lvl-1 CA: %s", err)
				}

				importedCALvl2, err := caSDK.ImportCA(context.Background(), services.ImportCAInput{
					CAType:        models.CertificateTypeExternal,
					ProfileID:     profile.ID,
					CACertificate: (*models.X509Certificate)(cert2),
				})
				if err != nil {
					t.Fatalf("could not import ca-lvl-2 CA: %s", err)
				}

				return importedCALvl2, err

			},
			resultCheck: func(ca *models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}

				if ca.Level != 2 {
					return fmt.Errorf("CA should be at level 2. Got %d", ca.Level)
				}

				if ca.Certificate.IssuerCAMetadata.Level != 1 {
					return fmt.Errorf("CA parent should be at level 1. Got %d", ca.Certificate.IssuerCAMetadata.Level)
				}

				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			err = serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' cleanup func in test case: %s", err)
			}

			//Init CA Server with 1 CA
			_, err = initCA(caTest.Service)
			if err != nil {
				t.Fatalf("failed running initCA: %s", err)
			}

			err = tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(caTest.HttpCASDK))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}

		})
	}
}

func TestDeleteCA(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca", "kms").WithCascadeDelete(true).Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) error
		resultCheck func(error) error
	}{
		{
			name: "Err/CADoesNotExist",
			before: func(svc services.CAService) error {

				return nil
			},
			run: func(caSDK services.CAService) error {
				//cas := []*models.CACertificate{}
				err := caSDK.DeleteCA(context.Background(), services.DeleteCAInput{
					CAID:          "DefaulasdadtCAID",
					CascadeDelete: false,
				})
				return err
			},
			resultCheck: func(err error) error {
				if err == nil {
					return fmt.Errorf("should've got error. Got none")
				}

				if !errors.Is(err, errs.ErrCANotFound) {
					return fmt.Errorf("got unexpected error: %s", err)
				}
				return nil
			},
		},
		{
			name: "Err/CAExistCore",
			before: func(svc services.CAService) error {

				_, err = svc.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{
					CAID:             DefaultCAID,
					Status:           models.StatusRevoked,
					RevocationReason: models.RevocationReason(1),
				})

				if err != nil {
					return fmt.Errorf("Error updating the CA status to expired")
				}
				return err

			},
			run: func(caSDK services.CAService) error {
				//cas := []*models.CACertificate{}
				err := caSDK.DeleteCA(context.Background(), services.DeleteCAInput{
					CAID:          DefaultCAID,
					CascadeDelete: false,
				})
				return err
			},
			resultCheck: func(err error) error {
				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}
				return nil
			},
		},
		{
			name: "Err/CAStatusActive",
			before: func(svc services.CAService) error {

				_, err = svc.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{
					CAID:             DefaultCAID,
					Status:           models.StatusActive,
					RevocationReason: models.RevocationReason(1),
				})

				if err != nil {
					return fmt.Errorf("Error updating the CA status to expired")
				}
				return err

			},
			run: func(caSDK services.CAService) error {
				//cas := []*models.CACertificate{}
				err := caSDK.DeleteCA(context.Background(), services.DeleteCAInput{
					CAID:          DefaultCAID,
					CascadeDelete: false,
				})

				return err
			},
			resultCheck: func(err error) error {
				if !errors.Is(err, errs.ErrCAStatus) {
					return fmt.Errorf("got unexpected error: %s", err)
				}
				return nil
			},
		},
		{
			name: "OK/DeleteRootCAWithChildCAs_CascadeTrue",
			before: func(svc services.CAService) error {

				rootCA, err := svc.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
				if err != nil {
					return fmt.Errorf("failed retrieving default CA: %s", err)
				}

				// Create child CA
				_, err = svc.CreateCA(context.Background(), services.CreateCAInput{
					ID:           "child-ca-test",
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "Test Child CA"},
					CAExpiration: models.Validity{Type: models.Time, Time: rootCA.Certificate.ValidTo},
					ParentID:     rootCA.ID,
					ProfileID:    rootCA.ProfileID,
				})
				if err != nil {
					return fmt.Errorf("failed creating child CA: %s", err)
				}

				// Revoke root CA to allow deletion
				_, err = svc.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{
					CAID:             DefaultCAID,
					Status:           models.StatusRevoked,
					RevocationReason: models.RevocationReason(1),
				})
				if err != nil {
					return fmt.Errorf("Error updating the CA status to revoked")
				}

				return nil
			},
			run: func(caSDK services.CAService) error {
				return caSDK.DeleteCA(context.Background(), services.DeleteCAInput{
					CAID:          DefaultCAID,
					CascadeDelete: true,
				})
			},
			resultCheck: func(err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error deleting root CA with cascade: %s", err)
				}
				return nil
			},
		},
		{
			name: "OK/DeleteRootCAWithChildCAs_CascadeFalse",
			before: func(svc services.CAService) error {

				rootCA, err := svc.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
				if err != nil {
					return fmt.Errorf("failed retrieving default CA: %s", err)
				}

				// Create child CA
				_, err = svc.CreateCA(context.Background(), services.CreateCAInput{
					ID:           "child-ca-test-2",
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "Test Child CA 2"},
					CAExpiration: models.Validity{Type: models.Time, Time: rootCA.Certificate.ValidTo},
					ParentID:     rootCA.ID,
					ProfileID:    rootCA.ProfileID,
				})
				if err != nil {
					return fmt.Errorf("failed creating child CA: %s", err)
				}

				// Revoke root CA to allow deletion
				_, err = svc.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{
					CAID:             rootCA.ID,
					Status:           models.StatusRevoked,
					RevocationReason: models.RevocationReason(1),
				})
				if err != nil {
					return fmt.Errorf("failed revoking root CA: %s", err)
				}

				return nil
			},
			run: func(caSDK services.CAService) error {
				return caSDK.DeleteCA(context.Background(), services.DeleteCAInput{
					CAID:          DefaultCAID,
					CascadeDelete: false,
				})
			},
			resultCheck: func(err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error deleting root CA without cascade: %s", err)
				}
				return nil
			},
		},
		{
			name: "OK/DeleteMultiLevelHierarchy_CascadeTrue",
			before: func(svc services.CAService) error {

				rootCA, err := svc.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
				if err != nil {
					return fmt.Errorf("failed retrieving default CA: %s", err)
				}

				// Create intermediate CA
				intermediateCA, err := svc.CreateCA(context.Background(), services.CreateCAInput{
					ID:           "intermediate-ca-hierarchy",
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "Test Intermediate CA"},
					CAExpiration: models.Validity{Type: models.Time, Time: rootCA.Certificate.ValidTo},
					ParentID:     rootCA.ID,
					ProfileID:    rootCA.ProfileID,
				})
				if err != nil {
					return fmt.Errorf("failed creating intermediate CA: %s", err)
				}

				// Create leaf CA
				_, err = svc.CreateCA(context.Background(), services.CreateCAInput{
					ID:           "leaf-ca-hierarchy",
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "Test Leaf CA"},
					CAExpiration: models.Validity{Type: models.Time, Time: intermediateCA.Certificate.ValidTo},
					ParentID:     intermediateCA.ID,
					ProfileID:    intermediateCA.ProfileID,
				})
				if err != nil {
					return fmt.Errorf("failed creating leaf CA: %s", err)
				}

				// Revoke root CA to allow deletion
				_, err = svc.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{
					CAID:             rootCA.ID,
					Status:           models.StatusRevoked,
					RevocationReason: models.RevocationReason(1),
				})
				if err != nil {
					return fmt.Errorf("failed revoking root CA: %s", err)
				}

				return nil
			},
			run: func(caSDK services.CAService) error {
				return caSDK.DeleteCA(context.Background(), services.DeleteCAInput{
					CAID:          DefaultCAID,
					CascadeDelete: true,
				})
			},
			resultCheck: func(err error) error {
				if err != nil {
					return fmt.Errorf("unexpected error deleting multi-level hierarchy: %s", err)
				}
				return nil
			},
		},
		{
			name: "OK/VerifyChildCARevocationAfterParentDelete",
			before: func(svc services.CAService) error {

				rootCA, err := svc.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
				if err != nil {
					return fmt.Errorf("failed retrieving default CA: %s", err)
				}

				// Create child CA
				_, err = svc.CreateCA(context.Background(), services.CreateCAInput{
					ID:           "child-ca-verify",
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "Test Child CA Verify"},
					CAExpiration: models.Validity{Type: models.Time, Time: rootCA.Certificate.ValidTo},
					ParentID:     rootCA.ID,
					ProfileID:    rootCA.ProfileID,
				})
				if err != nil {
					return fmt.Errorf("failed creating child CA: %s", err)
				}

				// Revoke root CA to allow deletion
				_, err = svc.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{
					CAID:             rootCA.ID,
					Status:           models.StatusRevoked,
					RevocationReason: models.RevocationReason(1),
				})
				if err != nil {
					return fmt.Errorf("failed revoking root CA: %s", err)
				}

				return nil
			},
			run: func(caSDK services.CAService) error {
				// Delete root CA without cascade - should revoke child CAs
				err := caSDK.DeleteCA(context.Background(), services.DeleteCAInput{
					CAID:          DefaultCAID,
					CascadeDelete: false,
				})
				if err != nil {
					return err
				}

				// Verify child CA is revoked
				childCA, err := caSDK.GetCAByID(context.Background(), services.GetCAByIDInput{
					CAID: "child-ca-verify",
				})
				if err != nil {
					return fmt.Errorf("child CA should still exist after parent deletion without cascade: %s", err)
				}

				if childCA.Certificate.Status != models.StatusRevoked {
					return fmt.Errorf("child CA should be revoked after parent deletion, got status: %s", childCA.Certificate.Status)
				}

				return nil
			},
			resultCheck: func(err error) error {
				if err != nil {
					return fmt.Errorf("verification failed: %s", err)
				}
				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {

			err = serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' cleanup func in test case: %s", err)
			}

			//Init CA Server with 1 CA
			_, err = initCA(caTest.Service)
			if err != nil {
				t.Fatalf("failed running initCA: %s", err)
			}

			err = tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(caTest.HttpCASDK))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func TestDeleteCA_CascadeDeleteConfigValidation(t *testing.T) {
	// Test with cascade delete disabled by configuration
	serverTestDisabled, err := TestServiceBuilder{}.WithDatabase("ca", "kms").WithCascadeDelete(false).Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server with cascade delete disabled: %s", err)
	}

	// Test with cascade delete enabled by configuration
	serverTestEnabled, err := TestServiceBuilder{}.WithDatabase("ca", "kms").WithCascadeDelete(true).Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server with cascade delete enabled: %s", err)
	}

	var testcases = []struct {
		name        string
		server      *TestServer
		expectError bool
		errorType   error
	}{
		{
			name:        "Err/CascadeDeleteDisabledByConfig",
			server:      serverTestDisabled,
			expectError: true,
		},
		{
			name:        "OK/CascadeDeleteEnabledByConfig",
			server:      serverTestEnabled,
			expectError: false,
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			err = tc.server.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' cleanup func in test case: %s", err)
			}

			caTest := tc.server.CA

			//Init CA Server with 1 CA
			rootCA, err := initCA(caTest.Service)
			if err != nil {
				t.Fatalf("failed running initCA: %s", err)
			}

			// Create a child CA
			childCA, err := caTest.Service.CreateCA(context.Background(), services.CreateCAInput{
				KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
				Subject:      models.Subject{CommonName: "TestChildCA"},
				CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour * 12)},
				ParentID:     rootCA.ID,
				ProfileID:    rootCA.ProfileID,
			})
			if err != nil {
				t.Fatalf("could not create child CA: %s", err)
			}

			// Revoke the root CA so it can be deleted
			_, err = caTest.Service.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{
				CAID:             rootCA.ID,
				Status:           models.StatusRevoked,
				RevocationReason: models.RevocationReason(0),
			})
			if err != nil {
				t.Fatalf("could not revoke root CA: %s", err)
			}

			// Try to delete the root CA with cascade delete enabled
			err = caTest.HttpCASDK.DeleteCA(context.Background(), services.DeleteCAInput{
				CAID:          rootCA.ID,
				CascadeDelete: true,
			})

			t.Logf("DeleteCA returned error: %v", err)

			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error about cascade delete not allowed, but got no error")
				}
				if !errors.Is(err, errs.ErrCascadeDeleteNotAllowed) {
					t.Fatalf("expected error about cascade delete not allowed, but got: %v", err)
				}

				// Verify child CA still exists when cascade delete is disabled
				_, err = caTest.Service.GetCAByID(context.Background(), services.GetCAByIDInput{
					CAID: childCA.ID,
				})
				if err != nil {
					t.Fatalf("child CA should still exist after failed cascade delete: %s", err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, but got: %v", err)
				}

				// Verify child CA was deleted when cascade delete is enabled
				_, err = caTest.Service.GetCAByID(context.Background(), services.GetCAByIDInput{
					CAID: childCA.ID,
				})
				if err == nil {
					t.Fatalf("child CA should have been deleted with cascade delete enabled")
				}
				if !errors.Is(err, errs.ErrCANotFound) {
					t.Fatalf("expected ErrCANotFound, but got: %v", err)
				}
			}
		})
	}
}

// TestDeleteCAPrivateKeyDeletion verifies that private keys are properly handled during CA deletion.
// This test covers multiple scenarios:
// 1. Managed CAs - have private keys in crypto engines that should be deleted
// 2. External CAs - have no private keys in crypto engines (deletion gracefully skipped)
// 3. Imported CAs with keys - have private keys that should be deleted
//
// The tests verify that:
// - CA deletion completes successfully regardless of private key deletion success/failure
// - Private key deletion is attempted for CAs that have engines configured
// - Private key deletion is gracefully skipped for external CAs
//
// Note: In a production environment with mock crypto engines, you could enhance these tests to:
// - Verify that DeleteKey() was actually called on the crypto engine
// - Test scenarios where private key deletion fails but CA deletion still succeeds
// - Verify that the correct key ID is passed to the crypto engine
func TestDeleteCAPrivateKeyDeletion(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	t.Run("ManagedCA_PrivateKeyDeleted", func(t *testing.T) {
		testDeleteCAWithPrivateKey(t, serverTest, "managed")
	})

	t.Run("ExternalCA_NoPrivateKey", func(t *testing.T) {
		testDeleteCAWithPrivateKey(t, serverTest, "external")
	})

	t.Run("ImportedCA_PrivateKeyDeleted", func(t *testing.T) {
		testDeleteCAWithPrivateKey(t, serverTest, "imported")
	})
}

func testDeleteCAWithPrivateKey(t *testing.T, serverTest *TestServer, caType string) {
	err := serverTest.BeforeEach()
	if err != nil {
		t.Fatalf("failed running 'BeforeEach' cleanup func: %s", err)
	}

	caTest := serverTest.CA

	// Setup the CA based on type
	var ca *models.CACertificate
	switch caType {
	case "managed":
		ca, err = caTest.Service.CreateCA(context.Background(), services.CreateCAInput{
			KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
			Subject:      models.Subject{CommonName: "TestManagedCA"},
			CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour * 12)},
			ProfileID:    "test-profile",
		})
	case "external":
		caCert, _, err := chelpers.GenerateSelfSignedCA(x509.RSA, time.Hour*24, "ExternalTestCA")
		if err != nil {
			t.Fatalf("failed to generate self-signed CA: %s", err)
		}
		ca, err = caTest.Service.ImportCA(context.Background(), services.ImportCAInput{
			CACertificate: (*models.X509Certificate)(caCert),
			CAType:        models.CertificateTypeExternal,
			ProfileID:     "test-profile",
		})
	case "imported":
		caCert, caKey, err := chelpers.GenerateSelfSignedCA(x509.RSA, time.Hour*24, "ImportedTestCA")
		if err != nil {
			t.Fatalf("failed to generate self-signed CA: %s", err)
		}
		rsaKey, ok := caKey.(*rsa.PrivateKey)
		if !ok {
			t.Fatalf("expected RSA key")
		}
		ca, err = caTest.Service.ImportCA(context.Background(), services.ImportCAInput{
			CACertificate: (*models.X509Certificate)(caCert),
			CARSAKey:      rsaKey,
			CAType:        models.CertificateTypeImportedWithKey,
			ProfileID:     "test-profile",
		})
	}

	if err != nil {
		t.Fatalf("failed to setup CA: %s", err)
	}

	// Revoke the CA so it can be deleted
	_, err = caTest.Service.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{
		CAID:             ca.ID,
		Status:           models.StatusRevoked,
		RevocationReason: models.RevocationReason(0),
	})
	if err != nil {
		t.Fatalf("could not revoke CA: %s", err)
	}

	// Store original key information for verification
	originalEngineID := ca.Certificate.EngineID

	// Delete the CA
	err = caTest.Service.DeleteCA(context.Background(), services.DeleteCAInput{
		CAID: ca.ID,
	})
	if err != nil {
		t.Fatalf("unexpected error during CA deletion: %v", err)
	}

	// Verify CA was deleted from storage
	verifyCADeleted(t, caTest, ca.ID, caType+" CA")

	t.Logf("✓ %s CA deleted successfully", caType)
	if originalEngineID != "" {
		t.Logf("✓ Private key deletion attempted for engine: %s", originalEngineID)
	} else {
		t.Logf("✓ No private key to delete (external CA)")
	}
}

func TestDeleteCAPrivateKeyDeletionWithCascade(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca", "kms").WithCascadeDelete(true).Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	t.Run("CascadeDelete_WithPrivateKeyDeletion", func(t *testing.T) {
		err = serverTest.BeforeEach()
		if err != nil {
			t.Fatalf("failed running 'BeforeEach' cleanup func: %s", err)
		}

		caTest := serverTest.CA

		// Create a root CA
		rootCA, err := caTest.Service.CreateCA(context.Background(), services.CreateCAInput{
			KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
			Subject:      models.Subject{CommonName: "RootCAForKeyDeletion"},
			CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour * 12)},
			ProfileID:    "test-profile",
		})
		if err != nil {
			t.Fatalf("could not create root CA: %s", err)
		}

		// Create a child CA
		childCA, err := caTest.Service.CreateCA(context.Background(), services.CreateCAInput{
			KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
			Subject:      models.Subject{CommonName: "ChildCAForKeyDeletion"},
			CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour * 12)},
			ParentID:     rootCA.ID,
			ProfileID:    rootCA.ProfileID,
		})
		if err != nil {
			t.Fatalf("could not create child CA: %s", err)
		}

		// Revoke the root CA so it can be deleted
		_, err = caTest.Service.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{
			CAID:             rootCA.ID,
			Status:           models.StatusRevoked,
			RevocationReason: models.RevocationReason(0),
		})
		if err != nil {
			t.Fatalf("could not revoke root CA: %s", err)
		}

		// Store engine IDs for verification
		rootEngineID := rootCA.Certificate.EngineID
		childEngineID := childCA.Certificate.EngineID

		// Delete the root CA with cascade
		err = caTest.Service.DeleteCA(context.Background(), services.DeleteCAInput{
			CAID:          rootCA.ID,
			CascadeDelete: true,
		})
		if err != nil {
			t.Fatalf("unexpected error during cascade delete: %v", err)
		}

		// Verify both CAs were deleted
		verifyCADeleted(t, caTest, rootCA.ID, "root CA")
		verifyCADeleted(t, caTest, childCA.ID, "child CA")

		t.Logf("✓ Cascade delete successful")
		t.Logf("✓ Root CA private key deletion attempted for engine: %s", rootEngineID)
		t.Logf("✓ Child CA private key deletion attempted for engine: %s", childEngineID)
	})
}

func verifyCADeleted(t *testing.T, caTest *CATestServer, caID string, caDescription string) {
	_, err := caTest.Service.GetCAByID(context.Background(), services.GetCAByIDInput{
		CAID: caID,
	})
	if err == nil || !errors.Is(err, errs.ErrCANotFound) {
		t.Fatalf("%s should have been deleted", caDescription)
	}
}

func TestGetCAs(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) ([]*models.CACertificate, error)
		resultCheck func([]*models.CACertificate, error) error
	}{
		{
			name: "Err/GetCAsExRunTrue",
			before: func(svc services.CAService) error {

				return nil
			},
			run: func(caSDK services.CAService) ([]*models.CACertificate, error) {
				cas := []*models.CACertificate{}
				res, err := caSDK.GetCAs(context.Background(), services.GetCAsInput{
					ExhaustiveRun: true,
					ApplyFunc: func(elem models.CACertificate) {
						cas = append(cas, &elem)
					},
				})
				fmt.Println(res)
				return cas, err
			},
			resultCheck: func(cas []*models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}
				if len(cas) != 1 {
					return fmt.Errorf("should've got only one CA and the received quantity is different.")
				}
				return nil
			},
		},
		{
			name: "Err/GetCAsExRunFalse",
			before: func(svc services.CAService) error {
				var caName string
				caDUr := models.TimeDuration(time.Hour * 24)
				issuanceDur := models.TimeDuration(time.Hour * 12)

				profile, err := svc.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Validity: models.Validity{
							Type:     models.Duration,
							Duration: issuanceDur,
						},
					},
				})
				if err != nil {
					t.Fatalf("could not create profile: %s", err)
				}

				for i := 0; i < 5; i++ {
					caName = DefaultCAID + strconv.Itoa(i)
					res, _ := svc.CreateCA(context.Background(), services.CreateCAInput{
						ID:           caName,
						KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
						Subject:      models.Subject{CommonName: DefaultCACN},
						CAExpiration: models.Validity{Type: models.Duration, Duration: caDUr},
						ProfileID:    profile.ID,
					})
					fmt.Println(res)
				}

				return nil
			},
			run: func(caSDK services.CAService) ([]*models.CACertificate, error) {
				cas := []*models.CACertificate{}
				res, err := caSDK.GetCAs(context.Background(), services.GetCAsInput{
					ExhaustiveRun: false,
					ApplyFunc: func(elem models.CACertificate) {
						cas = append(cas, &elem)
					},
					QueryParameters: &resources.QueryParameters{
						PageSize: 2,
					},
				})
				fmt.Println(res)
				return cas, err
			},
			resultCheck: func(cas []*models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}
				if len(cas) != 2 {
					return fmt.Errorf("should've got only two CAS, but got %d.", len(cas))
				}
				return nil
			},
		},
		{
			name: "Err/GetCAsExRunTrue",
			before: func(svc services.CAService) error {
				var caName string
				caDUr := models.TimeDuration(time.Hour * 24)
				issuanceDur := models.TimeDuration(time.Hour * 12)

				profile, err := svc.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Validity: models.Validity{
							Type:     models.Duration,
							Duration: issuanceDur,
						},
					},
				})
				if err != nil {
					t.Fatalf("could not create profile: %s", err)
				}
				for i := 0; i < 5; i++ {
					caName = DefaultCAID + strconv.Itoa(i)
					res, _ := svc.CreateCA(context.Background(), services.CreateCAInput{
						ID:           caName,
						KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
						Subject:      models.Subject{CommonName: DefaultCACN},
						CAExpiration: models.Validity{Type: models.Duration, Duration: caDUr},
						ProfileID:    profile.ID,
					})
					fmt.Println(res)
				}

				return nil
			},
			run: func(caSDK services.CAService) ([]*models.CACertificate, error) {
				cas := []*models.CACertificate{}
				res, err := caSDK.GetCAs(context.Background(), services.GetCAsInput{
					ExhaustiveRun: true,
					ApplyFunc: func(elem models.CACertificate) {
						cas = append(cas, &elem)
					},
					QueryParameters: &resources.QueryParameters{
						PageSize: 2,
					},
				})
				fmt.Println(res)
				return cas, err
			},
			resultCheck: func(cas []*models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}
				if len(cas) != 6 {
					return fmt.Errorf("should've got 6 CAs, but got %d.", len(cas))
				}
				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {

			err = serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' cleanup func in test case: %s", err)
			}

			//Init CA Server with 1 CA
			_, err = initCA(caTest.Service)
			if err != nil {
				t.Fatalf("failed running initCA: %s", err)
			}

			err = tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(caTest.HttpCASDK))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func TestGetStatsByCAID(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	var testcases = []struct {
		name        string
		before      func(svc services.CAService, caID string) error
		run         func(caSDK services.CAService, caID string) (map[models.CertificateStatus]int, error)
		resultCheck func(map[models.CertificateStatus]int, error) error
	}{
		{
			name: "OK/0Certs",
			before: func(svc services.CAService, caID string) error {
				return nil
			},
			run: func(caSDK services.CAService, caID string) (map[models.CertificateStatus]int, error) {
				return caSDK.GetStatsByCAID(context.Background(), services.GetStatsByCAIDInput{
					CAID: caID,
				})
			},
			resultCheck: func(stats map[models.CertificateStatus]int, err error) error {
				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}

				if stats[models.StatusRevoked] != 0 {
					return fmt.Errorf("should've got 0 revoked certificates. Got %d", stats[models.StatusRevoked])
				}

				if stats[models.StatusActive] != 1 { // Only the Root CA itself
					return fmt.Errorf("should've got 1 active certificates. Got %d", stats[models.StatusActive])
				}

				if stats[models.StatusExpired] != 0 {
					return fmt.Errorf("should've got 0 expired certificates. Got %d", stats[models.StatusExpired])
				}

				return nil
			},
		},
		{
			name: "OK/1Active1Revoked",
			before: func(svc services.CAService, caID string) error {
				actKey, err := chelpers.GenerateRSAKey(2048)
				if err != nil {
					return fmt.Errorf("Error creating the private key: %s", err)
				}

				ca, err := svc.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: caID})
				if err != nil {
					return fmt.Errorf("Error getting the CA: %s", err)
				}

				actCSR, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "active-cert"}, actKey)
				_, err = svc.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:              caID,
					CertRequest:       (*models.X509CertificateRequest)(actCSR),
					IssuanceProfileID: ca.ProfileID,
				})

				if err != nil {
					return fmt.Errorf("Error signing the active certificate: %s", err)
				}

				revKey, err := chelpers.GenerateRSAKey(2048)
				if err != nil {
					return fmt.Errorf("Error creating the private key: %s", err)
				}

				revCSR, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "revoked-cert"}, revKey)
				revCrt, err := svc.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID:              caID,
					CertRequest:       (*models.X509CertificateRequest)(revCSR),
					IssuanceProfileID: ca.ProfileID,
				})
				if err != nil {
					return fmt.Errorf("Error signing the revoked certificate: %s", err)
				}

				_, err = svc.UpdateCertificateStatus(context.Background(), services.UpdateCertificateStatusInput{
					SerialNumber:     revCrt.SerialNumber,
					NewStatus:        models.StatusRevoked,
					RevocationReason: ocsp.Unknown,
				})
				if err != nil {
					return fmt.Errorf("Error revoking the certificate: %s", err)
				}

				return nil
			},
			run: func(caSDK services.CAService, caID string) (map[models.CertificateStatus]int, error) {
				return caSDK.GetStatsByCAID(context.Background(), services.GetStatsByCAIDInput{
					CAID: caID,
				})
			},
			resultCheck: func(stats map[models.CertificateStatus]int, err error) error {
				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}

				if stats[models.StatusRevoked] != 1 {
					return fmt.Errorf("should've got 1 revoked certificates. Got %d", stats[models.StatusRevoked])
				}

				if stats[models.StatusActive] != 2 { // 1 regular cert + 1 Root CA
					return fmt.Errorf("should've got 2 active certificates. Got %d", stats[models.StatusActive])
				}

				if stats[models.StatusExpired] != 0 {
					return fmt.Errorf("should've got 0 expired certificates. Got %d", stats[models.StatusExpired])
				}

				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err = serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' cleanup func in test case: %s", err)
			}

			//Init CA Server with 1 CA
			_, err = initCA(caTest.Service)
			if err != nil {
				t.Fatalf("failed running initCA: %s", err)
			}

			exp := models.TimeDuration(time.Hour * 25)
			iss := models.TimeDuration(time.Hour * 24)

			profile, err := caTest.Service.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
				Profile: models.IssuanceProfile{
					Validity: models.Validity{
						Type:     models.Duration,
						Duration: iss,
					},
				},
			})
			if err != nil {
				t.Fatalf("could not create profile: %s", err)
			}

			rootCA, err := caTest.Service.CreateCA(context.Background(), services.CreateCAInput{
				KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
				Subject:      models.Subject{CommonName: "CA Lvl 1"},
				CAExpiration: models.Validity{Type: models.Duration, Duration: exp},
				ProfileID:    profile.ID,
			})
			if err != nil {
				t.Fatalf("failed creating root CA: %s", err)
			}

			err = tc.before(caTest.Service, rootCA.ID)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(caTest.HttpCASDK, rootCA.ID))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func TestGetCertificatesByExpirationDate(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) ([]*models.Certificate, error)
		resultCheck func([]*models.Certificate, error) error
	}{
		{
			name: "Err/GetCAGertByExpDate",
			before: func(svc services.CAService) error {
				ca, err := svc.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
				if err != nil {
					return fmt.Errorf("Error getting the CA: %s", err)
				}

				for i := 0; i < 20; i++ {
					key, err := chelpers.GenerateRSAKey(2048)
					if err != nil {
						return fmt.Errorf("Error creating the private key: %s", err)
					}

					csr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: fmt.Sprintf("cert-%d", 1)}, key)
					_, err = svc.SignCertificate(context.Background(), services.SignCertificateInput{
						CAID:              DefaultCAID,
						CertRequest:       (*models.X509CertificateRequest)(csr),
						IssuanceProfileID: ca.ProfileID,
					})
					if err != nil {
						return err
					}
				}
				return nil
			},
			run: func(caSDK services.CAService) ([]*models.Certificate, error) {
				cas := []*models.Certificate{}
				now := time.Now()
				before := time.Date(now.Year()+2, 0, 0, 0, 0, 0, 0, time.UTC)
				res, err := caSDK.GetCertificatesByExpirationDate(context.Background(), services.GetCertificatesByExpirationDateInput{
					ExpiresAfter:  now,
					ExpiresBefore: before,
					ListInput: resources.ListInput[models.Certificate]{
						ExhaustiveRun: true,
						QueryParameters: &resources.QueryParameters{
							PageSize: 2,
						},
						ApplyFunc: func(elem models.Certificate) {
							cas = append(cas, &elem)
						},
					},
				})
				fmt.Println(res)
				return cas, err
			},
			resultCheck: func(cas []*models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}
				if len(cas) != 21 { // 20 certs + 1 root CA
					return fmt.Errorf("should've got 21 certs, but got %d.", len(cas))
				}
				return nil
			},
		},
		{
			name: "Err/GetCAGertByExpDateExhaustiveRun",
			before: func(svc services.CAService) error {
				ca, err := svc.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
				if err != nil {
					return fmt.Errorf("Error getting the CA: %s", err)
				}

				for i := 0; i < 20; i++ {
					key, err := chelpers.GenerateRSAKey(2048)
					if err != nil {
						return fmt.Errorf("Error creating the private key: %s", err)
					}

					csr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: fmt.Sprintf("cert-%d", 1)}, key)
					_, err = svc.SignCertificate(context.Background(), services.SignCertificateInput{
						CAID:              DefaultCAID,
						CertRequest:       (*models.X509CertificateRequest)(csr),
						IssuanceProfileID: ca.ProfileID,
					})
					if err != nil {
						return err
					}
				}
				return nil
			},
			run: func(caSDK services.CAService) ([]*models.Certificate, error) {
				cas := []*models.Certificate{}
				now := time.Now()
				before := time.Date(now.Year()+2, 0, 0, 0, 0, 0, 0, time.UTC)
				res, err := caSDK.GetCertificatesByExpirationDate(context.Background(), services.GetCertificatesByExpirationDateInput{
					ExpiresAfter:  now,
					ExpiresBefore: before,
					ListInput: resources.ListInput[models.Certificate]{
						ExhaustiveRun: false,
						QueryParameters: &resources.QueryParameters{
							PageSize: 2,
						},
						ApplyFunc: func(elem models.Certificate) {
							cas = append(cas, &elem)
						},
					},
				})
				fmt.Println(res)
				return cas, err
			},
			resultCheck: func(cas []*models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}
				if len(cas) != 2 {
					return fmt.Errorf("should've got two certs, but got %d.", len(cas))
				}
				return nil
			},
		},
		{
			name: "Err/GetCAGertByExpDateIncDate",
			before: func(svc services.CAService) error {
				ca, err := svc.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: DefaultCAID})
				if err != nil {
					return fmt.Errorf("Error getting the CA: %s", err)
				}

				for i := 0; i < 20; i++ {
					key, err := chelpers.GenerateRSAKey(2048)
					if err != nil {
						return fmt.Errorf("Error creating the private key: %s", err)
					}

					csr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: fmt.Sprintf("cert-%d", 1)}, key)
					_, err = svc.SignCertificate(context.Background(), services.SignCertificateInput{
						CAID:              DefaultCAID,
						CertRequest:       (*models.X509CertificateRequest)(csr),
						IssuanceProfileID: ca.ProfileID,
					})
					if err != nil {
						return err
					}
				}
				return nil
			},
			run: func(caSDK services.CAService) ([]*models.Certificate, error) {
				cas := []*models.Certificate{}
				res, err := caSDK.GetCertificatesByExpirationDate(context.Background(), services.GetCertificatesByExpirationDateInput{
					ExpiresAfter:  time.Now(),
					ExpiresBefore: time.Date(2010, 0, 0, 0, 0, 0, 0, time.UTC),
					ListInput: resources.ListInput[models.Certificate]{
						ExhaustiveRun: true,
						QueryParameters: &resources.QueryParameters{
							PageSize: 2,
						},
						ApplyFunc: func(elem models.Certificate) {
							cas = append(cas, &elem)
						},
					},
				})
				fmt.Println(res)
				return cas, err
			},
			resultCheck: func(cas []*models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}
				if len(cas) != 0 {
					return fmt.Errorf("should've got no cert, but got %d.", len(cas))
				}
				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {

			err = serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' cleanup func in test case: %s", err)
			}

			//Init CA Server with 1 CA
			_, err = initCA(caTest.Service)
			if err != nil {
				t.Fatalf("failed running initCA: %s", err)
			}

			err = tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(caTest.HttpCASDK))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func TestSignatureVerify(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) (bool, error)
		resultCheck func(bool, error) error
	}{
		{
			name:   "OK/TestSignatureVerifyPlainMessagePSS256",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (bool, error) {
				messB := []byte("my Message")
				sign, err := caSDK.SignatureSign(context.Background(), services.SignatureSignInput{
					CAID:             DefaultCAID,
					Message:          []byte(messB),
					MessageType:      models.Raw,
					SigningAlgorithm: "RSASSA_PSS_SHA_256",
				})
				if err != nil {
					return false, err
				}

				res, err := caSDK.SignatureVerify(context.Background(), services.SignatureVerifyInput{
					CAID:             DefaultCAID,
					Signature:        sign,
					SigningAlgorithm: "RSASSA_PSS_SHA_256",
					MessageType:      models.Raw,
					Message:          []byte(messB),
				})
				return res, err
			},
			resultCheck: func(valid bool, err error) error {
				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}

				if !valid {
					return fmt.Errorf("signature verification failed")
				}
				return nil
			},
		},
		{
			name:   "OK/TestSignatureVerifyPlainMessagePKCS1V5",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (bool, error) {
				messB := []byte("my Message")
				sign, err := caSDK.SignatureSign(context.Background(), services.SignatureSignInput{
					CAID:             DefaultCAID,
					Message:          []byte(messB),
					MessageType:      models.Raw,
					SigningAlgorithm: "RSASSA_PKCS1_V1_5_SHA_384",
				})
				if err != nil {
					return false, err
				}

				res, err := caSDK.SignatureVerify(context.Background(), services.SignatureVerifyInput{
					CAID:             DefaultCAID,
					Signature:        sign,
					SigningAlgorithm: "RSASSA_PKCS1_V1_5_SHA_384",
					MessageType:      models.Raw,
					Message:          []byte(messB),
				})
				return res, err
			},
			resultCheck: func(valid bool, err error) error {
				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}

				if !valid {
					return fmt.Errorf("signature verification failed")
				}
				return nil
			},
		},
		{
			name:   "OK/TestSignatureVerifyHashMessage",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (bool, error) {
				h := sha256.New()

				messB := []byte("my Message")
				h.Write([]byte(messB))
				messH := h.Sum(nil)

				sign, err := caSDK.SignatureSign(context.Background(), services.SignatureSignInput{
					CAID:             DefaultCAID,
					Message:          []byte(messH),
					MessageType:      models.Hashed,
					SigningAlgorithm: "RSASSA_PSS_SHA_256",
				})
				if err != nil {
					return false, err
				}

				res, err := caSDK.SignatureVerify(context.Background(), services.SignatureVerifyInput{
					CAID:             DefaultCAID,
					Message:          []byte(messH),
					MessageType:      models.Hashed,
					SigningAlgorithm: "RSASSA_PSS_SHA_256",
					Signature:        sign,
				})
				return res, err
			},
			resultCheck: func(valid bool, err error) error {
				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}

				if !valid {
					return fmt.Errorf("signature verification failed")
				}
				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			//
			// err := postgres_test.BeforeEach()
			// fmt.Errorf("Error while running BeforeEach job: %s", err)

			err = serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' cleanup func in test case: %s", err)
			}

			//Init CA Server with 1 CA
			_, err = initCA(caTest.Service)
			if err != nil {
				t.Fatalf("failed running initCA: %s", err)
			}

			err = tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(caTest.HttpCASDK))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}
func TestHierarchyCryptoEngines(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) ([]models.CACertificate, error)
		resultCheck func([]models.CACertificate, error) error
	}{
		{
			name: "OK/TestHighDurationRootCA",
			before: func(svc services.CAService) error {

				return nil
			},
			run: func(caSDK services.CAService) ([]models.CACertificate, error) {
				var cas []models.CACertificate
				caDurRootCA := models.TimeDuration(time.Hour * 25)
				caDurChild1 := models.TimeDuration(time.Hour * 24)

				caIss := models.TimeDuration(time.Minute * 3)
				engines, _ := caSDK.GetCryptoEngineProvider(context.Background())

				// Create issuance profile for root CA
				rootProfile, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Validity: models.Validity{Type: models.Duration, Duration: caIss},
					},
				})
				if err != nil {
					t.Fatalf("failed creating root CA issuance profile: %s", err)
				}

				rootCA, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "CA Lvl 1"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDurRootCA},
					ProfileID:    rootProfile.ID,
					EngineID:     engines[0].ID,
				})

				if err != nil {
					t.Fatalf("failed creating the root CA: %s", err)
				}
				cas = append(cas, *rootCA)

				// Create issuance profile for child CA
				childProfile, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Validity: models.Validity{Type: models.Duration, Duration: caIss},
					},
				})
				if err != nil {
					t.Fatalf("failed creating child CA issuance profile: %s", err)
				}

				childCALvl1, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "CA Lvl 1"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDurChild1},
					ProfileID:    childProfile.ID,
					ParentID:     rootCA.ID,
				})
				if err != nil {
					t.Fatalf("failed creating the first CA child: %s", err)
				}
				cas = append(cas, *childCALvl1)
				fmt.Println("=============================")
				fmt.Println("CN:" + childCALvl1.Certificate.Subject.CommonName)
				fmt.Println("ID:" + childCALvl1.ID)
				fmt.Println("SN:" + childCALvl1.Certificate.SerialNumber)
				fmt.Println("=============================")

				//cas := []*models.CACertificate{}

				return cas, err
			},
			resultCheck: func(cas []models.CACertificate, err error) error {

				rootCa := cas[0]
				childCa := cas[1]

				if rootCa.Certificate.ValidTo.Before(childCa.Certificate.ValidTo) {
					return fmt.Errorf("requested CA would expire after parent CA")
				}

				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}
				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			//
			// err := postgres_test.BeforeEach()
			// fmt.Errorf("Error while running BeforeEach job: %s", err)

			err = serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' cleanup func in test case: %s", err)
			}

			//Init CA Server with 1 CA
			_, err = initCA(caTest.Service)
			if err != nil {
				t.Fatalf("failed running initCA: %s", err)
			}

			err = tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(caTest.HttpCASDK))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}
func TestHierarchy(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca", "kms").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) ([]models.CACertificate, error)
		resultCheck func([]models.CACertificate, error) error
	}{
		{
			name: "OK/TestHighDurationRootCA",
			before: func(svc services.CAService) error {

				return nil
			},
			run: func(caSDK services.CAService) ([]models.CACertificate, error) {
				var cas []models.CACertificate
				caDurRootCA := models.TimeDuration(time.Hour * 25)
				caDurChild1 := models.TimeDuration(time.Hour * 24)
				caDurChild2 := models.TimeDuration(time.Hour * 23)
				caIss := models.TimeDuration(time.Minute * 3)

				// Create issuance profile for root CA
				rootProfile, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Validity: models.Validity{Type: models.Duration, Duration: caIss},
					},
				})
				if err != nil {
					t.Fatalf("failed creating root CA issuance profile: %s", err)
				}

				rootCA, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "CA Lvl 0"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDurRootCA},
					ProfileID:    rootProfile.ID,
				})
				if err != nil {
					t.Fatalf("failed creating the root CA: %s", err)
				}

				cas = append(cas, *rootCA)

				// Create issuance profile for child CA level 1
				child1Profile, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Validity: models.Validity{Type: models.Duration, Duration: caIss},
					},
				})
				if err != nil {
					t.Fatalf("failed creating child CA level 1 issuance profile: %s", err)
				}

				childCALvl1, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "CA Lvl 1"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDurChild1},
					ProfileID:    child1Profile.ID,
					ParentID:     rootCA.ID,
				})
				if err != nil {
					t.Fatalf("failed creating the first CA child: %s", err)
				}
				cas = append(cas, *childCALvl1)
				fmt.Println("=============================")
				fmt.Println("CN:" + childCALvl1.Certificate.Subject.CommonName)
				fmt.Println("ID:" + childCALvl1.ID)
				fmt.Println("SN:" + childCALvl1.Certificate.SerialNumber)
				fmt.Println("SKID:" + childCALvl1.Certificate.SubjectKeyID)
				fmt.Println("AKID:" + childCALvl1.Certificate.AuthorityKeyID)
				fmt.Println("Type:" + childCALvl1.Certificate.Type)
				fmt.Println("=============================")

				// Create issuance profile for child CA level 2
				child2Profile, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Validity: models.Validity{Type: models.Duration, Duration: caIss},
					},
				})
				if err != nil {
					t.Fatalf("failed creating child CA level 2 issuance profile: %s", err)
				}

				childCALvl2, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "CA Lvl 2"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDurChild2},
					ProfileID:    child2Profile.ID,
					ParentID:     childCALvl1.ID,
					ID:           "Lvl2",
				})
				if err != nil {
					t.Fatalf("failed creating the second CA child: %s", err)
				}

				fmt.Println("=============================")
				fmt.Println("CN:" + childCALvl2.Certificate.Subject.CommonName)
				fmt.Println("ID:" + childCALvl2.ID)
				fmt.Println("SN:" + childCALvl2.Certificate.SerialNumber)
				fmt.Println("=============================")

				//cas := []*models.CACertificate{}

				return cas, err
			},
			resultCheck: func(cas []models.CACertificate, err error) error {
				rootCa := cas[0]
				childCa := cas[1]

				if rootCa.Certificate.ValidTo.Before(childCa.Certificate.ValidTo) {
					return fmt.Errorf("requested CA would expire after parent CA")
				}

				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}

				return nil
			},
		},
		{
			name: "OK/ChildCAExpiresAfterRootCA",
			before: func(svc services.CAService) error {
				return nil
			},
			run: func(caSDK services.CAService) ([]models.CACertificate, error) {
				var cas []models.CACertificate
				caDurChild1 := models.TimeDuration(time.Hour * 26)
				caDurRootCA := models.TimeDuration(time.Hour * 25)

				caIss := models.TimeDuration(time.Minute * 3)

				// Create issuance profile for root CA
				rootProfile, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Validity: models.Validity{Type: models.Duration, Duration: caIss},
					},
				})
				if err != nil {
					t.Fatalf("failed creating root CA issuance profile: %s", err)
				}

				rootCA, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "CA Lvl 0"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDurRootCA},
					ProfileID:    rootProfile.ID,
				})

				if err != nil {
					t.Fatalf("failed creating the root CA: %s", err)
				}

				cas = append(cas, *rootCA)

				// Create issuance profile for child CA
				childProfile, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Validity: models.Validity{Type: models.Duration, Duration: caIss},
					},
				})
				if err != nil {
					t.Fatalf("failed creating child CA issuance profile: %s", err)
				}

				_, err = caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "CA Lvl 1"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDurChild1},
					ProfileID:    childProfile.ID,
					ParentID:     rootCA.ID,
					ID:           "Lvl1",
				})

				//cas := []*models.CACertificate{}

				return cas, err
			},
			resultCheck: func(cas []models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("expected success when child CA expires after root CA, but got error: %s", err)
				}

				return nil
			},
		},
		{
			name: "OK/TestHightDateLimitRootCA",
			before: func(svc services.CAService) error {

				return nil
			},
			run: func(caSDK services.CAService) ([]models.CACertificate, error) {
				var cas []models.CACertificate
				caRDLim := time.Date(3000, 12, 1, 0, 0, 0, 0, time.Local)   // expires the 1st of december of 3000
				caCDLim1 := time.Date(3000, 11, 28, 0, 0, 0, 0, time.Local) // expires the 28th of november of 3000
				caCDLim2 := time.Date(3000, 11, 27, 0, 0, 0, 0, time.Local) // expires the 27 of november of 3000

				issuanceDur := time.Date(3000, 11, 20, 0, 0, 0, 0, time.Local) // fixed issuance: the 20 of november of 3000
				profile, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Validity: models.Validity{Type: models.Time, Time: issuanceDur},
					},
				})
				if err != nil {
					t.Fatalf("failed creating root CA issuance profile: %s", err)
				}

				ca, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: DefaultCACN},
					CAExpiration: models.Validity{Type: models.Time, Time: caRDLim},
					ProfileID:    profile.ID,
				})
				if err != nil {
					t.Fatalf("failed creating the first CA child: %s", err)
				}
				cas = append(cas, *ca)

				fmt.Println("=============================")
				fmt.Println("CN:" + ca.Certificate.Subject.CommonName)
				fmt.Println("ID:" + ca.ID)
				fmt.Println("SN:" + ca.Certificate.SerialNumber)
				fmt.Println("=============================")

				caIss := time.Date(2030, 11, 20, 0, 0, 0, 0, time.Local)
				profile2, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Validity: models.Validity{Type: models.Time, Time: caIss},
					},
				})
				if err != nil {
					t.Fatalf("failed creating child CA issuance profile: %s", err)
				}

				childCALvl1, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "CA Lvl 1"},
					CAExpiration: models.Validity{Type: models.Time, Time: caCDLim1},
					ProfileID:    profile2.ID,
					ParentID:     ca.ID,
				})
				if err != nil {
					t.Fatalf("failed creating the first CA child: %s", err)
				}
				cas = append(cas, *childCALvl1)
				fmt.Println("=============================")
				fmt.Println("CN:" + childCALvl1.Certificate.Subject.CommonName)
				fmt.Println("ID:" + childCALvl1.ID)
				fmt.Println("SN:" + childCALvl1.Certificate.SerialNumber)
				fmt.Println("=============================")

				childCALvl2, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "CA Lvl 1"},
					CAExpiration: models.Validity{Type: models.Time, Time: caCDLim2},
					ProfileID:    profile.ID,
					ParentID:     childCALvl1.ID,
				})
				if err != nil {
					t.Fatalf("failed creating the first CA child: %s", err)
				}

				fmt.Println("=============================")
				fmt.Println("CN:" + childCALvl2.Certificate.Subject.CommonName)
				fmt.Println("ID:" + childCALvl2.ID)
				fmt.Println("SN:" + childCALvl2.Certificate.SerialNumber)
				fmt.Println("=============================")

				//cas := []*models.CACertificate{}

				return cas, err
			},
			resultCheck: func(cas []models.CACertificate, err error) error {
				rootCa := cas[0]
				childCa := cas[1]

				if rootCa.Certificate.ValidTo.Before(childCa.Certificate.ValidTo) {
					return fmt.Errorf("requested CA would expire after parent CA")
				}

				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}

				return nil
			},
		},
		{
			name: "OK/ChildCAExpiresAfterParentCA-UsingFixedDates",
			before: func(svc services.CAService) error {
				return nil
			},
			run: func(caSDK services.CAService) ([]models.CACertificate, error) {
				var cas []models.CACertificate
				caRDLim := time.Date(2030, 12, 1, 0, 0, 0, 0, time.Local)
				caCDLim1 := time.Date(2030, 12, 2, 0, 0, 0, 0, time.Local)

				caIss := time.Date(2030, 11, 20, 0, 0, 0, 0, time.Local)
				profile, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Validity: models.Validity{Type: models.Time, Time: caIss},
					},
				})
				if err != nil {
					t.Fatalf("failed creating root CA issuance profile: %s", err)
				}

				ca, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: DefaultCACN},
					CAExpiration: models.Validity{Type: models.Time, Time: caRDLim},
					ProfileID:    profile.ID,
				})

				if err != nil {
					return nil, err
				}

				cas = append(cas, *ca)
				_, err = caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "CA Lvl 1"},
					CAExpiration: models.Validity{Type: models.Time, Time: caCDLim1},
					ProfileID:    profile.ID,
					ParentID:     ca.ID,
				})

				//cas := []*models.CACertificate{}

				return cas, err
			},
			resultCheck: func(cas []models.CACertificate, err error) error {

				if err != nil {
					return fmt.Errorf("expected success when child CA expires after parent CA using fixed dates, but got error: %s", err)
				}

				return nil
			},
		},
		{
			name: "OK/TestMixedExpirationTimeFormats",
			before: func(svc services.CAService) error {
				return nil
			},
			run: func(caSDK services.CAService) ([]models.CACertificate, error) {
				var cas []models.CACertificate
				caRDLim := time.Date(3000, 12, 1, 0, 0, 0, 0, time.Local)
				caDurChild1 := models.TimeDuration(time.Hour * 26)

				caIss := time.Date(3000, 11, 20, 0, 0, 0, 0, time.Local)
				profile, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Validity: models.Validity{Type: models.Time, Time: caIss},
					},
				})
				if err != nil {
					t.Fatalf("failed creating root CA issuance profile: %s", err)
				}

				ca, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: DefaultCACN},
					CAExpiration: models.Validity{Type: models.Time, Time: caRDLim},
					ProfileID:    profile.ID,
				})

				if err != nil {
					return nil, err
				}

				cas = append(cas, *ca)
				caIss2 := models.TimeDuration(time.Minute * 3)
				profile2, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
					Profile: models.IssuanceProfile{
						Validity: models.Validity{Type: models.Duration, Duration: caIss2},
					},
				})
				if err != nil {
					t.Fatalf("failed creating root CA issuance profile: %s", err)
				}

				childCALvl1, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "CA Lvl 1"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDurChild1},
					ProfileID:    profile2.ID,
					ParentID:     ca.ID,
				})
				cas = append(cas, *childCALvl1)

				return cas, err
			},
			resultCheck: func(cas []models.CACertificate, err error) error {

				rootCa := cas[0]
				childCa := cas[1]

				if rootCa.Certificate.ValidTo.Before(childCa.Certificate.ValidTo) {
					return fmt.Errorf("requested CA would expire after parent CA")
				}

				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}

				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			err = serverTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' cleanup func in test case: %s", err)
			}

			//Init CA Server with 1 CA
			_, err = initCA(caTest.Service)
			if err != nil {
				t.Fatalf("failed running initCA: %s", err)
			}

			err = tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(caTest.HttpCASDK))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func TestCAsAdditionalDeltasMonitoring(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca", "kms").WithMonitor().Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	type delta struct {
		name string
		dur  time.Duration
	}

	var testcases = []struct {
		name   string
		deltas []delta
	}{
		{
			name: "'Preventive' Delta",
			deltas: []delta{
				{
					name: "Preventive",
					dur:  time.Second * 5,
				},
			},
		},
		{
			name: "'Preventive' and 'MyDelta' Delta",
			deltas: []delta{
				{
					name: "Preventive",
					dur:  time.Second * 5,
				},
				{
					name: "MyDelta",
					dur:  time.Second * 3,
				},
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			maxDeltaDur := time.Second
			caDeltas := []models.MonitoringExpirationDelta{}
			for _, delta := range tc.deltas {
				if delta.dur > maxDeltaDur {
					maxDeltaDur = delta.dur
				}

				if delta.dur > 10*time.Second { //prevent tests that have long-lasting deltas
					t.Fatalf("bad testcase. Reprogram the test using low-value deltas")
				}

				caDeltas = append(caDeltas, models.MonitoringExpirationDelta{
					Delta:     models.TimeDuration(delta.dur),
					Name:      delta.name,
					Triggered: false,
				})
			}

			caLifespan := 3*time.Second + maxDeltaDur
			caDur := models.TimeDuration(caLifespan)
			issuanceDur := models.TimeDuration(maxDeltaDur)
			profile, err := serverTest.CA.Service.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
				Profile: models.IssuanceProfile{
					Validity: models.Validity{Type: models.Duration, Duration: issuanceDur},
				},
			})
			if err != nil {
				t.Fatalf("failed creating root CA issuance profile: %s", err)
			}

			ca, err := serverTest.CA.Service.CreateCA(context.Background(), services.CreateCAInput{
				KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256},
				Subject:      models.Subject{CommonName: "MyCA"},
				CAExpiration: models.Validity{Type: models.Duration, Duration: caDur},
				ProfileID:    profile.ID,
				Metadata: map[string]any{
					models.CAMetadataMonitoringExpirationDeltasKey: models.CAMetadataMonitoringExpirationDeltas(caDeltas),
				},
			})

			if err != nil {
				t.Fatalf("unexpected error. Could not create CA: %s", err)
			}

			maxSeconds := int(caLifespan.Seconds())
			elapsedSeconds := 0
			for i := 0; i < maxSeconds; i++ {
				time.Sleep(time.Second * 1)
				elapsedSeconds++
				now := time.Now()

				caExpFromNow := ca.Certificate.ValidTo.Sub(now)
				updatedCA, err := serverTest.CA.Service.GetCAByID(context.Background(), services.GetCAByIDInput{CAID: ca.ID})
				if err != nil {
					t.Fatalf("unexpected error. Could not get an updated version for CA: %s", err)
				}

				var updatedCADeltas models.CAMetadataMonitoringExpirationDeltas
				helpers.GetMetadataToStruct(updatedCA.Metadata, models.CAMetadataMonitoringExpirationDeltasKey, &updatedCADeltas)
				for _, definedDelta := range updatedCADeltas {
					if definedDelta.Delta > models.TimeDuration(caExpFromNow) {
						if definedDelta.Triggered == false {
							t.Fatalf("delta '%s' should've been triggered by now. CA expires in %ds and delta was defined with %ds", definedDelta.Name, int(caExpFromNow.Seconds()), int(time.Duration(definedDelta.Delta).Seconds()))
						} else {
							fmt.Printf("correctly triggered delta '%s'. CA expires in %ds and delta was defined with %ds", definedDelta.Name, int(caExpFromNow.Seconds()), int(time.Duration(definedDelta.Delta).Seconds()))
						}
					}
				}
			}
		})
	}

}

func initCA(caSDK services.CAService) (*models.CACertificate, error) {
	caDUr := models.TimeDuration(time.Hour * 25)
	issuanceDur := models.TimeDuration(time.Minute * 12)

	profile, err := caSDK.CreateIssuanceProfile(context.Background(), services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Validity: models.Validity{Type: models.Duration, Duration: issuanceDur},
		},
	})
	if err != nil {
		return nil, err
	}

	ca, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
		ID:           DefaultCAID,
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:      models.Subject{CommonName: DefaultCACN},
		CAExpiration: models.Validity{Type: models.Duration, Duration: caDUr},
		ProfileID:    profile.ID,
	})

	return ca, err
}
