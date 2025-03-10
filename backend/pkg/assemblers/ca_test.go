package assemblers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"slices"
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

var DefaultCAID = "111111-2222"

const DefaultCACN = "MyCA"

func TestCryptoEngines(t *testing.T) {
	//serverTest, err := StartCAServiceTestServer(t, false)
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").WithVault().Build(t)
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
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	caDUr := models.TimeDuration(time.Hour * 24)

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) (*models.Certificate, error)
		resultCheck func(createdCA *models.Certificate, err error) error
	}{
		{
			name:   "OK/KeyType-RSA",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.Certificate, error) {
				return caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "TestCA"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDUr},
				})
			},
			resultCheck: func(createdCA *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've created CA without error, but got error: %s", err)
				}

				return nil
			},
		},
		{
			name:   "OK/KeyType-ECC",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.Certificate, error) {
				return caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256},
					Subject:      models.Subject{CommonName: "TestCA"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDUr},
				})
			},
			resultCheck: func(createdCA *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've created CA without error, but got error: %s", err)
				}

				return nil
			},
		},
		{
			name:   "OK/Expiration-Duration",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.Certificate, error) {
				return caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "TestCA"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDUr},
				})
			},
			resultCheck: func(createdCA *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've created CA without error, but got error: %s", err)
				}

				return nil
			},
		},
		{
			name:   "OK/Expiration-Time",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.Certificate, error) {
				tCA := time.Date(9999, 11, 31, 23, 59, 59, 0, time.UTC)
				return caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "TestCA"},
					CAExpiration: models.Validity{Type: models.Time, Time: tCA},
				})
			},
			resultCheck: func(createdCA *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've created CA without error, but got error: %s", err)
				}

				if createdCA.ValidTo.Year() != 9999 {
					t.Fatalf("CA certificate should expire on 9999 but got %d", createdCA.ValidTo.Year())
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
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	caDUr := models.TimeDuration(time.Hour * 24)
	issuanceDur := models.TimeDuration(time.Hour * 12)

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
				enrollCA, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{

					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "TestCA"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDUr},
				})

				if err != nil {
					t.Fatalf("could not create CA: %s", err)
				}

				commonName := fmt.Sprintf("enrolled-%s", uuid.NewString())
				enrollKey, _ := chelpers.GenerateRSAKey(2048)
				enrollCSR, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: commonName}, enrollKey)

				crt, err := caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
					SubjectKeyID: enrollCA.SubjectKeyID,
					CertRequest:  (*models.X509CertificateRequest)(enrollCSR),
					IssuanceProfile: models.IssuanceProfile{
						Validity:        models.Validity{Type: models.Duration, Duration: issuanceDur},
						SignAsCA:        false,
						HonorSubject:    true,
						HonorExtensions: true,
					},
				})
				if err != nil {
					t.Fatalf("could not sign the certificate: %s", err)
				}

				_, err = caSDK.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{
					SubjectKeyID:     enrollCA.SubjectKeyID,
					Status:           models.StatusRevoked,
					RevocationReason: models.RevocationReason(0),
				})

				if err != nil {
					t.Fatalf("could not update the status of the CA: %s", err)
				}

				err = caSDK.DeleteCA(context.Background(), services.DeleteCAInput{
					SubjectKeyID: enrollCA.SubjectKeyID,
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
				importedCALvl1, err := caSDK.ImportCertificate(context.Background(), services.ImportCertificateInput{
					Certificate: ca,
				})

				if err != nil {
					return nil, fmt.Errorf("got unexpected error, while importing the CA: %s", err)
				}

				err = caSDK.DeleteCA(context.Background(), services.DeleteCAInput{
					SubjectKeyID: importedCALvl1.SubjectKeyID,
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
				ca1, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{

					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "TestCA"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDUr},
				})

				if err != nil {
					t.Fatalf("could not create CA: %s", err)
				}

				_, err = caSDK.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{
					SubjectKeyID:     ca1.SubjectKeyID,
					Status:           models.StatusRevoked,
					RevocationReason: models.RevocationReason(0),
				})
				if err != nil {
					t.Fatalf("error while changing the status of the CA: %s", err)
				}

				err = caSDK.DeleteCA(context.Background(), services.DeleteCAInput{
					SubjectKeyID: ca1.SubjectKeyID,
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
				ca1, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "TestCA"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDUr},
				})

				if err != nil {
					t.Fatalf("could not create CA: %s", err)
				}

				_, err = caSDK.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{
					SubjectKeyID: ca1.SubjectKeyID,
					Status:       models.StatusExpired,
				})
				if err != nil {
					t.Fatalf("error while changing the status of the CA: %s", err)
				}

				err = caSDK.DeleteCA(context.Background(), services.DeleteCAInput{
					SubjectKeyID: ca1.SubjectKeyID,
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
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").Build(t)
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
				_, err := svc.GetCAByID(context.Background(), services.GetCAByIDInput{SubjectKeyID: DefaultCAID})
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
						SubjectKeyID: DefaultCAID,
						CertRequest:  (*models.X509CertificateRequest)(csr),
						IssuanceProfile: models.IssuanceProfile{
							//Validity:        ca.Validity,
							SignAsCA:        false,
							HonorSubject:    true,
							HonorExtensions: true,
						},
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
					SubjectKeyID: DefaultCAID,
					Status:       models.StatusActive,
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
				_, err := svc.GetCAByID(context.Background(), services.GetCAByIDInput{SubjectKeyID: DefaultCAID})
				if err != nil {
					return fmt.Errorf("Error getting the CA: %s", err)
				}

				certsToIssue := 15
				for i := 0; i < certsToIssue; i++ {
					key, _ := chelpers.GenerateRSAKey(2048)
					csr, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: fmt.Sprintf("cert-%d", i)}, key)
					_, err := svc.SignCertificate(context.Background(), services.SignCertificateInput{
						SubjectKeyID: DefaultCAID,
						CertRequest:  (*models.X509CertificateRequest)(csr),
						IssuanceProfile: models.IssuanceProfile{
							//Validity:        ca.Validity,
							SignAsCA:        false,
							HonorSubject:    true,
							HonorExtensions: true,
						},
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
					SubjectKeyID: DefaultCAID,
					Status:       models.StatusActive,
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
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	var testcases = []struct {
		name        string
		run         func(caSDK services.CAService, caIDToSign string) (*models.Certificate, error)
		resultCheck func(issuedCerts *models.Certificate, err error) error
	}{
		{
			name: "OK/SignCertificate",
			run: func(caSDK services.CAService, caIDToSign string) (*models.Certificate, error) {
				key, err := chelpers.GenerateRSAKey(2048)
				if err != nil {
					return nil, err
				}

				csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "test", Country: "ES", Organization: "lamassu", OrganizationUnit: "iot", State: "lamassu-world", Locality: "lamassu-city"}, key)
				if err != nil {
					return nil, err
				}

				return caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
					SubjectKeyID: caIDToSign,
					CertRequest:  (*models.X509CertificateRequest)(csr),
					IssuanceProfile: models.IssuanceProfile{
						//Validity:        validity,
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
			name: "OK/SignCertificateWithAltSubject",
			run: func(caSDK services.CAService, caIDToSign string) (*models.Certificate, error) {
				key, err := chelpers.GenerateRSAKey(2048)
				if err != nil {
					return nil, err
				}

				csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "test", Country: "ES", Organization: "lamassu", OrganizationUnit: "iot", State: "lamassu-world", Locality: "lamassu-city"}, key)
				if err != nil {
					return nil, err
				}

				return caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
					SubjectKeyID: caIDToSign,
					CertRequest:  (*models.X509CertificateRequest)(csr),
					IssuanceProfile: models.IssuanceProfile{
						//Validity:     validity,
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
			run: func(caSDK services.CAService, caIDToSign string) (*models.Certificate, error) {
				key, err := chelpers.GenerateRSAKey(2048)
				if err != nil {
					return nil, err
				}

				csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "test", Country: "ES", Organization: "lamassu", OrganizationUnit: "iot", State: "lamassu-world", Locality: "lamassu-city"}, key)
				if err != nil {
					return nil, err
				}

				return caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
					SubjectKeyID: caIDToSign,
					CertRequest:  (*models.X509CertificateRequest)(csr),
					IssuanceProfile: models.IssuanceProfile{
						//Validity:        validity,
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
			name: "Err/CADoesNotExist",
			run: func(caSDK services.CAService, caIDToSign string) (*models.Certificate, error) {
				key, err := chelpers.GenerateRSAKey(2048)
				if err != nil {
					return nil, err
				}

				csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "test", Country: "ES", Organization: "lamassu", OrganizationUnit: "iot", State: "lamassu-world", Locality: "lamassu-city"}, key)
				if err != nil {
					return nil, err
				}

				return caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
					SubjectKeyID: "myCA",
					CertRequest:  (*models.X509CertificateRequest)(csr),
					IssuanceProfile: models.IssuanceProfile{
						//Validity:        validity,
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

			ca, err := caTest.Service.CreateCA(context.Background(), services.CreateCAInput{
				KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
				Subject:      models.Subject{CommonName: "TestCA"},
				CAExpiration: models.Validity{Type: models.Duration, Duration: caExpiration},
			})
			if err != nil {
				t.Fatalf("failed creating CA: %s", err)
			}

			err = tc.resultCheck(tc.run(caTest.HttpCASDK, ca.SubjectKeyID))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func TestImportCertificate(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	var testcases = []struct {
		name        string
		run         func(caSDK services.CAService) (*models.Certificate, *models.Certificate, error)
		resultCheck func(importedCert *models.Certificate, ca *models.Certificate, err error) error
	}{
		{
			name: "OK/ImportCertificate",
			run: func(caSDK services.CAService) (*models.Certificate, *models.Certificate, error) {
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
				//issuanceDur := models.TimeDuration(time.Hour * 2)
				importedCA, err := caSDK.ImportCertificate(context.Background(), services.ImportCertificateInput{
					PrivateKey:  caKey.(*ecdsa.PrivateKey),
					Certificate: ca,
				})
				if err != nil {
					t.Fatalf("failed importing CA: %s", err)
				}

				//Import Certificate
				importedCert, err := caSDK.ImportCertificate(context.Background(), services.ImportCertificateInput{
					Certificate: cert,
				})

				return importedCert, importedCA, err
			},
			resultCheck: func(importedCert *models.Certificate, ca *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error but got error: %s", err)
				}

				if importedCert == nil {
					return fmt.Errorf("should've got imported certificate but got nil")
				}

				if importedCert.IssuerCAMetadata.Level != ca.Level {
					return fmt.Errorf("imported certificate should have Level %d but got %d", ca.Level, importedCert.IssuerCAMetadata.Level)
				}

				if importedCert.IssuerCAMetadata.ID != ca.SubjectKeyID {
					return fmt.Errorf("imported certificate should have CAID %s but got %s", ca.SubjectKeyID, importedCert.IssuerCAMetadata.ID)
				}

				if importedCert.IssuerCAMetadata.SN != ca.SerialNumber {
					return fmt.Errorf("imported certificate should have SerialNumber %s but got %s", ca.SerialNumber, importedCert.IssuerCAMetadata.SN)
				}

				if importedCert.Status != models.StatusActive {
					return fmt.Errorf("imported certificate should have Active status but got %s", importedCert.Status)
				}

				return nil
			},
		},
		{
			name: "OK/ExpiredCert",
			run: func(caSDK services.CAService) (*models.Certificate, *models.Certificate, error) {
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
				importedCA, err := caSDK.ImportCertificate(context.Background(), services.ImportCertificateInput{
					PrivateKey:  caKey,
					Certificate: ca,
				})
				if err != nil {
					t.Fatalf("failed importing CA: %s", err)
				}

				//Import Certificate
				importedCert, err := caSDK.ImportCertificate(context.Background(), services.ImportCertificateInput{
					Certificate: cert,
				})

				return importedCert, importedCA, err
			},
			resultCheck: func(importedCert *models.Certificate, ca *models.Certificate, err error) error {
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
			run: func(caSDK services.CAService) (*models.Certificate, *models.Certificate, error) {
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
					Certificate: cert,
				})

				return importedCert, nil, err
			},
			resultCheck: func(importedCert *models.Certificate, ca *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error but got error: %s", err)
				}

				if importedCert == nil {
					return fmt.Errorf("should've got imported certificate but got nil")
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
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA
	issuanceDur := models.TimeDuration(time.Hour * 12)

	var testcases = []struct {
		name        string
		run         func(caSDK services.CAService) (*models.Certificate, error)
		resultCheck func(revokedCA *models.Certificate, issuedCerts []*models.Certificate, err error) error
	}{
		{
			name: "OK/RevokeWith0CertsIssued",
			run: func(caSDK services.CAService) (*models.Certificate, error) {
				return caSDK.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{
					SubjectKeyID:     DefaultCAID,
					Status:           models.StatusRevoked,
					RevocationReason: ocsp.AACompromise,
				})
			},
			resultCheck: func(revokedCA *models.Certificate, issuedCerts []*models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error but got error: %s", err)
				}

				if revokedCA.Status != models.StatusRevoked {
					return fmt.Errorf("CA should have Revoked status but is in %s status", revokedCA.Status)
				}

				if revokedCA.RevocationReason != ocsp.AACompromise {
					return fmt.Errorf("CA should have RevocationReason AACompromise status but is in %s reason", revokedCA.RevocationReason)
				}

				return nil
			},
		},
		{
			name: "OK/RevokeWith20CertsIssued",
			run: func(caSDK services.CAService) (*models.Certificate, error) {
				_, err := caSDK.GetCAByID(context.Background(), services.GetCAByIDInput{SubjectKeyID: DefaultCAID})
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
						SubjectKeyID: DefaultCAID,
						CertRequest:  (*models.X509CertificateRequest)(csr),
						IssuanceProfile: models.IssuanceProfile{
							Validity:        models.Validity{Type: models.Duration, Duration: issuanceDur},
							SignAsCA:        false,
							HonorSubject:    true,
							HonorExtensions: true,
						},
					})
				}
				caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
					SubjectKeyID: DefaultCAID,
				})

				return caSDK.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{
					SubjectKeyID:     DefaultCAID,
					Status:           models.StatusRevoked,
					RevocationReason: ocsp.AACompromise,
				})
			},
			resultCheck: func(revokedCA *models.Certificate, issuedCerts []*models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error but got error: %s", err)
				}

				if revokedCA.Status != models.StatusRevoked {
					return fmt.Errorf("CA should have Revoked status but is in %s status", revokedCA.Status)
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
				SubjectKeyID: DefaultCAID,
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
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").Build(t)
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
				//cas := []*models.Certificate{}
				_, err := caSDK.UpdateCAMetadata(context.Background(), services.UpdateCAMetadataInput{
					SubjectKeyID: DefaultCAID,
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
				//cas := []*models.Certificate{}
				_, err := caSDK.UpdateCAMetadata(context.Background(), services.UpdateCAMetadataInput{
					SubjectKeyID: "sdfsfgsd",
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
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").Build(t)
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
			name:   "OK/CAsCommonName",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) ([]*models.Certificate, error) {
				cas := []*models.Certificate{}
				_, err := caSDK.GetCAsByCommonName(context.Background(), services.GetCAsByCommonNameInput{
					CommonName: DefaultCACN,
					ApplyFunc: func(cert models.Certificate) {
						cas = append(cas, &cert)
					},
				})
				return cas, err
			},
			resultCheck: func(cas []*models.Certificate, err error) error {
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
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").Build(t)
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
					SubjectKeyID: DefaultCAID,
					CertRequest:  (*models.X509CertificateRequest)(csr),
					IssuanceProfile: models.IssuanceProfile{
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
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").WithMonitor().Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) (*models.Certificate, error)
		run         func(caSDK services.CAService, caCreated *models.Certificate) (*models.Certificate, error)
		resultCheck func(*models.Certificate, error) error
	}{
		{
			name: "OK/UpdateExpiredCAStatus",
			before: func(svc services.CAService) (*models.Certificate, error) {
				//Create Out of Band CA
				ca, err := svc.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256},
					Subject:      models.Subject{CommonName: "myCA"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Second * 2)},
					Metadata:     map[string]any{},
				})
				if err != nil {
					return nil, fmt.Errorf("Got error while creating the CA %s", err)
				}

				//Wait for the CA to expire
				time.Sleep(time.Second * 5)
				return ca, nil
			},
			run: func(caSDK services.CAService, caCreated *models.Certificate) (*models.Certificate, error) {
				caStatus := models.StatusExpired
				res, err := caSDK.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{
					SubjectKeyID:     caCreated.SubjectKeyID,
					Status:           caStatus,
					RevocationReason: models.RevocationReason(2),
				})

				return res, err
			},
			resultCheck: func(cas *models.Certificate, err error) error {
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
			before: func(svc services.CAService) (*models.Certificate, error) { return nil, nil },
			run: func(caSDK services.CAService, _ *models.Certificate) (*models.Certificate, error) {
				caStatus := models.StatusExpired
				res, err := caSDK.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{
					SubjectKeyID:     "sdadaad",
					Status:           caStatus,
					RevocationReason: models.RevocationReason(2),
				})

				if err != nil {
					return nil, fmt.Errorf("Got error while updating the status of the CA %s", err)
				}

				ca, err := caSDK.GetCAByID(context.Background(), services.GetCAByIDInput{
					SubjectKeyID: DefaultCAID,
				})
				if err != nil {
					return nil, fmt.Errorf("Got error while checking the status of the CA %s", err)
				}
				if ca.Status != caStatus {
					return nil, fmt.Errorf("should've got no error, but got error: %s", err)
				}
				return res, err
			},
			resultCheck: func(cas *models.Certificate, err error) error {
				if err == nil {
					return fmt.Errorf("should've got no error, but got error: %s", err)
				}
				return nil
			},
		},
		{
			name:   "OK/UpdateCAStatusRevoked",
			before: func(svc services.CAService) (*models.Certificate, error) { return nil, nil },
			run: func(caSDK services.CAService, _ *models.Certificate) (*models.Certificate, error) {
				caStatus := models.StatusRevoked
				//cas := []*models.Certificate{}
				res, err := caSDK.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{
					SubjectKeyID:     DefaultCAID,
					Status:           caStatus,
					RevocationReason: models.RevocationReason(2),
				})

				if err != nil {
					return nil, fmt.Errorf("unexpected status for CA")
				}

				ca, err := caSDK.GetCAByID(context.Background(), services.GetCAByIDInput{
					SubjectKeyID: DefaultCAID,
				})
				if err != nil {
					return nil, fmt.Errorf("Got error while checking CA status  %s", err)
				}
				if ca.Status != caStatus {
					return nil, fmt.Errorf("unexpected status for CA")
				}
				return res, err
			},
			resultCheck: func(cas *models.Certificate, err error) error {
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

			caCreated, err := tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(caTest.HttpCASDK, caCreated))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func TestGetStats(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").Build(t)
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
				//cas := []*models.Certificate{}
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
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA
	issuanceDur := models.TimeDuration(time.Hour * 12)

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) ([]*models.Certificate, error)
		resultCheck func([]*models.Certificate, error) error
	}{
		{
			name: "OK/GetsCertificatesEXRunTrue",
			before: func(svc services.CAService) error {
				_, err := svc.GetCAByID(context.Background(), services.GetCAByIDInput{SubjectKeyID: DefaultCAID})
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
						SubjectKeyID: DefaultCAID,
						CertRequest:  (*models.X509CertificateRequest)(csr),
						IssuanceProfile: models.IssuanceProfile{
							Validity:        models.Validity{Type: models.Duration, Duration: issuanceDur},
							SignAsCA:        false,
							HonorSubject:    true,
							HonorExtensions: true,
						},
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
				_, err := svc.GetCAByID(context.Background(), services.GetCAByIDInput{SubjectKeyID: DefaultCAID})
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
						SubjectKeyID: DefaultCAID,
						CertRequest:  (*models.X509CertificateRequest)(csr),
						IssuanceProfile: models.IssuanceProfile{
							Validity:        models.Validity{Type: models.Duration, Duration: issuanceDur},
							SignAsCA:        false,
							HonorSubject:    true,
							HonorExtensions: true,
						},
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
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA
	issuanceDur := models.TimeDuration(time.Hour * 12)

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) ([]*models.Certificate, error)
		resultCheck func([]*models.Certificate, error) error
	}{
		{
			name: "OK/GetCertificatesByCAExRunFalse",
			before: func(svc services.CAService) error {
				_, err := svc.GetCAByID(context.Background(), services.GetCAByIDInput{SubjectKeyID: DefaultCAID})
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
						SubjectKeyID: DefaultCAID,
						CertRequest:  (*models.X509CertificateRequest)(csr),
						IssuanceProfile: models.IssuanceProfile{
							Validity:        models.Validity{Type: models.Duration, Duration: issuanceDur},
							SignAsCA:        false,
							HonorSubject:    true,
							HonorExtensions: true,
						},
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
					SubjectKeyID: DefaultCAID,
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
				_, err := svc.GetCAByID(context.Background(), services.GetCAByIDInput{SubjectKeyID: DefaultCAID})
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
						SubjectKeyID: DefaultCAID,
						CertRequest:  (*models.X509CertificateRequest)(csr),
						IssuanceProfile: models.IssuanceProfile{
							Validity:        models.Validity{Type: models.Duration, Duration: issuanceDur},
							SignAsCA:        false,
							HonorSubject:    true,
							HonorExtensions: true,
						},
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
					SubjectKeyID: DefaultCAID,
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
				_, err := svc.GetCAByID(context.Background(), services.GetCAByIDInput{SubjectKeyID: DefaultCAID})
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
						SubjectKeyID: DefaultCAID,
						CertRequest:  (*models.X509CertificateRequest)(csr),
						IssuanceProfile: models.IssuanceProfile{
							Validity:        models.Validity{Type: models.Duration, Duration: issuanceDur},
							SignAsCA:        false,
							HonorSubject:    true,
							HonorExtensions: true,
						},
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
					SubjectKeyID: "NonExistenCAID",
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
				_, err := svc.GetCAByID(context.Background(), services.GetCAByIDInput{SubjectKeyID: DefaultCAID})
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
						SubjectKeyID: DefaultCAID,
						CertRequest:  (*models.X509CertificateRequest)(csr),
						IssuanceProfile: models.IssuanceProfile{
							Validity:        models.Validity{Type: models.Duration, Duration: issuanceDur},
							SignAsCA:        false,
							HonorSubject:    true,
							HonorExtensions: true,
						},
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
					SubjectKeyID: "NonExistenCAID",
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
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").WithVault().Build(t)
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
		run         func(caSDK services.CAService) (*models.Certificate, error)
		resultCheck func(*models.Certificate, error) error
	}{
		{
			name:   "OK/ImportingExternalCA",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.Certificate, error) {
				ca, _, err := generateSelfSignedCA(x509.RSA)
				if err != nil {
					return nil, fmt.Errorf("Failed creating the certificate %s", err)
				}

				importedCA, err := caSDK.ImportCertificate(context.Background(), services.ImportCertificateInput{
					Certificate: ca,
				})

				return importedCA, err
			},
			resultCheck: func(ca *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}

				return nil
			},
		},
		{
			name:   "OK/ImportingExternalCA",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.Certificate, error) {
				ca, key, err := generateSelfSignedCA(x509.RSA)
				if err != nil {
					return nil, fmt.Errorf("Failed creating the certificate %s", err)
				}

				importedCA, err := caSDK.ImportCertificate(context.Background(), services.ImportCertificateInput{
					Certificate: ca,
					PrivateKey:  key,
				})

				return importedCA, err
			},
			resultCheck: func(cas *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}

				return nil
			},
		},
		{
			name:   "OK/ImportingToSpecificEngine",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.Certificate, error) {
				ca, key, err := generateSelfSignedCA(x509.RSA)
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

				importedCA, err := caSDK.ImportCertificate(context.Background(), services.ImportCertificateInput{
					Certificate: ca,
					PrivateKey:  key,
					EngineID:    engine.ID,
				})

				return importedCA, err
			},
			resultCheck: func(cas *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}
				return nil
			},
		},
		{
			name:   "OK/ImportingCAWithECDSAKey",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.Certificate, error) {
				ca, key, err := generateSelfSignedCA(x509.ECDSA)
				if err != nil {
					return nil, fmt.Errorf("Failed creating the certificate %s", err)
				}

				importedCA, err := caSDK.ImportCertificate(context.Background(), services.ImportCertificateInput{
					Certificate: ca,
					PrivateKey:  key,
				})
				return importedCA, err
			},
			resultCheck: func(cas *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}
				return nil
			},
		},
		{
			name:   "OK/ImportingCAWithoutID",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.Certificate, error) {
				ca, key, err := generateSelfSignedCA(x509.RSA)
				if err != nil {
					return nil, fmt.Errorf("Failed creating the certificate %s", err)
				}

				importedCA, err := caSDK.ImportCertificate(context.Background(), services.ImportCertificateInput{
					Certificate: ca,
					PrivateKey:  key,
				})

				return importedCA, err
			},
			resultCheck: func(cas *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}
				return nil
			},
		},
		// 		{
		// 			name:   "OK/ImportingHierarchy",
		// 			before: func(svc services.CAService) error { return nil },
		// 			run: func(caSDK services.CAService) (*models.Certificate, error) {
		// 				ca0Crt := `-----BEGIN CERTIFICATE-----
		// MIIF4TCCA8mgAwIBAgIQD7Bwh2HNiZht1NqCrgyw+TANBgkqhkiG9w0BAQsFADAS
		// MRAwDgYDVQQDEwdSb290LUNBMCAXDTI0MDUyMDEwMjA0MloYDzk5OTkxMjMxMjI1
		// OTU5WjASMRAwDgYDVQQDEwdSb290LUNBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
		// MIICCgKCAgEA1N9HcHVVIpUm/JmPVxEasRsoh4Dh6+/CX/hex7prZ+OEkqwFFfYx
		// vnSGX0lQyDGnymjyLEtC+dumW7PrJ1wuQaI6uZ+Jy5XGPLiPVc/EzGPxnKJV6OF6
		// nkDPc3qPorzMM1s4JZX2D4YfasumEmREYQsdufMik3iiJ5AbojUuVQLIsqnxrJZ7
		// FOSkM4pux47f6o2nOKIhkoUQ8zAQ950yXON0F573GS87PLRx8XuMj79o4DsHQ8w3
		// 38M8/vIhwlQMmaqx7+gLN2fKRw4wHUfnJRmPwmszAQtjMCk+mEO5C2xAi5tzf9Ec
		// hUHlrwUQRJhCit3yTrqzKDMCfAel/qllrB6wGI+p37PTg5AM5e3cmK80jmKwXiQM
		// RHdbNwnvrnxQnpBZBvtR2uH/v3z85BmkNxMrQsGQLBlYm/WIcv3zOzyJUJcAv46f
		// t4Wv/MuAjmWVSkrO0uZgJkwoV7jFTJq5qrIPs1us7L1/pfJPlew+e1lpvAy2oTKB
		// FroJffAsIf2Su2VsqygzMOZHjnb/EIyIZ0dOudHOSuFBYlSS+cyLQYnTunaACPmL
		// jb9SkXWi/ps/X20QbEUuXMTuG7oUrsKwYVSCofr74R5cvT6PeQflvB2XbDjOKMDN
		// uaQHhOOVLYeV3A2NSkYTjKAVBtpj0YbnPDQ+/ImygvswwCr7hc9OyZsCAwEAAaOC
		// AS8wggErMA4GA1UdDwEB/wQEAwIBljAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYB
		// BQUHAwEwDwYDVR0TAQH/BAUwAwEB/zAtBgNVHQ4EJgQkOWViY2EzMDEtOWZkYy00
		// ZDI0LWEzZmItMzIzZGExYjliNTExMC8GA1UdIwQoMCaAJDllYmNhMzAxLTlmZGMt
		// NGQyNC1hM2ZiLTMyM2RhMWI5YjUxMTA3BggrBgEFBQcBAQQrMCkwJwYIKwYBBQUH
		// MAGGG2h0dHBzOi8vbGFiLmxhbWFzc3UuaW8vb2NzcDBQBgNVHR8ESTBHMEWgQ6BB
		// hj9odHRwczovL2xhYi5sYW1hc3N1LmlvL2NybC85ZWJjYTMwMS05ZmRjLTRkMjQt
		// YTNmYi0zMjNkYTFiOWI1MTEwDQYJKoZIhvcNAQELBQADggIBAIWs+bveoWQsUPeR
		// 4en3nDJf8xfbPjCA6u9TZvED/B+J6U2db8S6aS32b5q6xFvFMgFKCY1ezeFXlbwl
		// 52zoGDMKRK5XnvOgQVDaP123e8SAjAY+ZdD1ZQlg7JwaKV9cz7aAHv4RbU1E48IY
		// GPFUzh9KXjH6CxjJxF29PjROuBadltuPSupxdjY+Gwvid+uQCSJ80Fpza4kWf4Z6
		// GNkNJ3D7N+WImXCW1za+V0kvM3hQTCRx9rebvIrC96XkDCcfUftsmok/N9qK5xq9
		// 8iLSWlygzgPyb30Dre2E5MfTS3M48v2cUiWgKHvXIcP5EMyR2RAIpfvAiXcTvgU0
		// 5CTsep3MQXr4t4q/CkwwWsof1imTQEeTBMxa+0vTXT1kZSnrlojJweysatYnfW0F
		// c2ICmNRBnaJFr9hsPuyvT9ZpoEUh2Gme0mPG4kXZ2t9MLdUYByJMMb8O7CSmEUOA
		// 7Nv0yD6wd+WkZku3XrWRw0Wp9wQnX6IcNrH/gfvBTu60ePKBYVeQCrX8Rl6R7baX
		// IqUV1Fvtc2Q9GPK8jY2/WZBC38LAOOFgoXAllsxmHYrJJhC8uR+l7IIZNrMCsjre
		// v5gs9H66gdr0B6RB5VVfWxZ34Indlrkd+OR6oRT3fE+3F0o9uMzuk3FKJw9C2Ee/
		// VISVtZ9f3pwAsoxH/6bz+qzThkK4
		// -----END CERTIFICATE-----
		// `

		// 				ca0Key := `-----BEGIN RSA PRIVATE KEY-----
		// MIIJKAIBAAKCAgEA1N9HcHVVIpUm/JmPVxEasRsoh4Dh6+/CX/hex7prZ+OEkqwF
		// FfYxvnSGX0lQyDGnymjyLEtC+dumW7PrJ1wuQaI6uZ+Jy5XGPLiPVc/EzGPxnKJV
		// 6OF6nkDPc3qPorzMM1s4JZX2D4YfasumEmREYQsdufMik3iiJ5AbojUuVQLIsqnx
		// rJZ7FOSkM4pux47f6o2nOKIhkoUQ8zAQ950yXON0F573GS87PLRx8XuMj79o4DsH
		// Q8w338M8/vIhwlQMmaqx7+gLN2fKRw4wHUfnJRmPwmszAQtjMCk+mEO5C2xAi5tz
		// f9EchUHlrwUQRJhCit3yTrqzKDMCfAel/qllrB6wGI+p37PTg5AM5e3cmK80jmKw
		// XiQMRHdbNwnvrnxQnpBZBvtR2uH/v3z85BmkNxMrQsGQLBlYm/WIcv3zOzyJUJcA
		// v46ft4Wv/MuAjmWVSkrO0uZgJkwoV7jFTJq5qrIPs1us7L1/pfJPlew+e1lpvAy2
		// oTKBFroJffAsIf2Su2VsqygzMOZHjnb/EIyIZ0dOudHOSuFBYlSS+cyLQYnTunaA
		// CPmLjb9SkXWi/ps/X20QbEUuXMTuG7oUrsKwYVSCofr74R5cvT6PeQflvB2XbDjO
		// KMDNuaQHhOOVLYeV3A2NSkYTjKAVBtpj0YbnPDQ+/ImygvswwCr7hc9OyZsCAwEA
		// AQKCAgBznsKiplgTbIe8c3uTgsrIn0OoNayABb3BepmgSfTEfKMpNx2cDBiApbHG
		// V3/0/GNyYQYIYOiD5XW6IUL8IelN5NuYrrqdRUBjAqt3pF3z1eUJenLHBpEfG3yR
		// 8GPLtFgFHOqmH4mCbQrraqlNHAC35N3Effaturv4WSFpPRFpQxXXVM7bOvCnLHiz
		// NeFtqoCcWUwWSpmJh5TpQZY1p8APC8umeMUlfK3kDu5EhyKVgRVplSYhAO7oLpcW
		// slT7w8MEQ95Zu+M7uLf5WA9yF/fIAtY+dxNA4fqB0iUZds8vESENsuVM6ztedahX
		// I5zuZPTfkCVn9agRkYMr8suKQl/h2sW9SpvsE8TPAzn4BRqhcALT8tfZaQ2RhdqX
		// aBfjZueT6mlzN+FFa/SMOmfc+DLupIAqD+vox3ikhrM5Fpy9kE0yF0ZVum/XyvpA
		// b+3nhbFGQZUqtx6N3FEnJQAomZtuNsquzqgj6I51izCjgWiTv5U0m4iOayLJoS/u
		// TsH1zakp2NMYZrty49VwzzCGpTWxExeP2k4Cy9EdI4BhzwFxDC7q9tp0xOs6lgIf
		// grzARiu6bI5XyHEPve8nH1kmy1INYOev87VuxDmO2Y6FpZxm5uXF4LaQstPZyujp
		// oI9YamT7PMmwJ4MeRh405dBh0plN22c98mpw95oeQ5Mpbp5JQQKCAQEA+FzMBvkU
		// Y12f/ejap+I0neXsOZTK+0WfKMAnx4nJGVej4BVDKzinhY/kt1YP5TZUNYqwYBqo
		// RlIBqY3H9hw+SFpF12JRhwmXiDTC9hjRDlJJhYHB9WTq1z+vxsF4j+sg2qzeTOtM
		// D/pi2M/weESdRv6MjvUJdsQqnd5O0mTpXGHeq5a3nmThHveE7pIfppbCRrsM3lCb
		// zr9nd1iD+nVd2eJNgwb5p226wC6kCo3UdqMaq8hDZ1s8tn0ud5c8d7fTtXNUXQg2
		// xkJk2mg14br0snadcIWFUwGNH7wljLdCfjsqY1HtyLSl/qgQDKrIFEyhszJp1YJr
		// 4/xcL8XHmsbSeQKCAQEA22sWy06QOoE0CF4D+R8jHvDhlJVuY2Ha/a66NDiInu5Q
		// qNyX/aIuWMTyZcUJ/8ksUAsUHtk+/RoivqW4R3W5hA7OMKR2tjik3+wzAAWA2J9Y
		// qbellG2L3oyiJc0SmS0C74PukIh6NgEXEuUs50ZSlAmE7Ltkyelcu+5Q7WPEyVt/
		// tP7+UBmOH1aQEqvmPelt76DbzLMCr4Uqjk8MVd+xBDPiVmwPS+ccxpuH5HMu5bmi
		// vFQRHQySeJmus6E3sMWwCNRS+NixUpskndJnkUgeL4R7FJmjC37t5jpAhNvXAIM+
		// fzB7ANBJ5cXyxqploBddKswCc+tBKZfw0E7DZjbXswKCAQEAiJJOx07UfUeQoQkY
		// o9Tp5iH24jsF22KPgNMZjMohwUPGI4TNqMjApdtYg9BZcUuMxtx63H4MJo8Vxuzm
		// Flm1jgfF/AhemIkXwJhy1O0UmHF7aGTQCWbzFGY6/GqLJ2i+akFBBL8m1mpzTJIb
		// w6bHbbCwDjSEfcClRqZmZZ+EC37t+SEp23nRqTum56GGsg6Yylg1XVKqOuhZtvD/
		// sgw0DYo54WFGi2D1npSHNB6FxK8wDWJUXlN3cUoo8S5C2/pD+rVuoLHRnPgJiWhg
		// qL4rrK85KBTkGZ7ywY6uf1COyeczCeaVgRaFaSF1oeGPoEn7aRTBydysA3RUJRj3
		// CA9o0QKCAQBWXlfxnTIupU8bAA7mT/heJIlXGF8EZa9y7gVDqwE0NjCv121InD9M
		// F/ImVyIxejmkJEg+QFuH+3Kzwr2/+zoUHlPRV9uWrMNRlUMZ/hCStF6NJ8nYnCpT
		// Zt4orQlmHA6swyzz3ZTljxZLDMTZIJg+x2R4Xuc0h1RGcW+PkhcS/55MW5c1ZmnI
		// MiWyA9I0ip8IlTQP5mLnPi7bJ4h+gPfH5LhyNkTrJsTv9KbQKPrL2H+TTDAUVC+P
		// o0beVFZ8kcRSJWmnpHxgPMt0CC9WQ6IGKEred/9y9fqlBkcBRRvjisXeAPJaBqMf
		// /AQtaUNpeejlgLpycKcMvU9AX9CQeoP7AoIBAFtjG7YHerqeeIwbl2cHAVxSsi2M
		// obI3vTel5CBrllK9BuF2jOX2+boe+zQL4lbd9gudpiKJCDuB62ZesnS9pgayEO10
		// zjD2fB+6XqcIspg6Lqs8vabP9Sn7kBgVrop5SFhS5qGVmN/qkx2KWUKxOyrAdDXy
		// Tva4L2jpl+ldMF8LTgIDIF7I0m9LkPR3IDARKGIBC6zaO1duknDOIPZdajpSWy1C
		// CftA4H7VAl0dXVJ9i0rLQpxTg+dNfjbE2u81HJzLM4C/I1n07fIkWMSesuk1TA6h
		// VVCUToNHo7n7ZMiTGsu8/NBt+rbCpY+ZXQUbaWsLXv5w0fUH8H33kApKr2w=
		// -----END RSA PRIVATE KEY-----
		// `

		// 				ca1Crt := `-----BEGIN CERTIFICATE-----
		// MIIEGzCCAgOgAwIBAgIRAPvXcyzJg5xcaH+Q3ieTJ/wwDQYJKoZIhvcNAQELBQAw
		// EjEQMA4GA1UEAxMHUm9vdC1DQTAgFw0yNDA1MjAxMDI5MzZaGA85OTk5MDMxNjEx
		// Mjg1NVowFjEUMBIGA1UEAxMLTHZsLTEtQ0EtRUMwWTATBgcqhkjOPQIBBggqhkjO
		// PQMBBwNCAAQKXQjvwtkS4lMROVD6/oW047XdqPYAeyvAdWcTCGevarLuAAkPKU8J
		// HycPx9FRmDkunk2l7Dtu59CFOfDxvvnMo4IBLzCCASswDgYDVR0PAQH/BAQDAgGW
		// MB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAPBgNVHRMBAf8EBTADAQH/
		// MC0GA1UdDgQmBCRhOWI3ODJlMC04NTEyLTRkMDUtYTNiOS03ZmQ0MmJhMDhkOWIw
		// LwYDVR0jBCgwJoAkOWViY2EzMDEtOWZkYy00ZDI0LWEzZmItMzIzZGExYjliNTEx
		// MDcGCCsGAQUFBwEBBCswKTAnBggrBgEFBQcwAYYbaHR0cHM6Ly9sYWIubGFtYXNz
		// dS5pby9vY3NwMFAGA1UdHwRJMEcwRaBDoEGGP2h0dHBzOi8vbGFiLmxhbWFzc3Uu
		// aW8vY3JsL2E5Yjc4MmUwLTg1MTItNGQwNS1hM2I5LTdmZDQyYmEwOGQ5YjANBgkq
		// hkiG9w0BAQsFAAOCAgEAwPErojapNGN8BtD4L9q4H/byIkxpXoiv6eCRtxk9MCc8
		// rnnEZCE5tt/dtkifQUAIMRwGfQTXC2QEFKvSday1Nt9GEGj3KaeFyi9UTfpwtJIZ
		// rzkMO0pYwyC3/OCh3RTJ0wJpqVP99kUMTcaDnc1BzmPXORlMneMp0nxUe5zHdsUx
		// DYj6N1dbozazGyL9x6cOLrqfOwD6R1PGPXbMOtEAQyTY/Yv0qSTGMG6twAM7NT1G
		// om4VWZXkq4WsgOmxYax+YWqQ6FyixV/LJML/maS04ZFhH4kFeyfp0RHm9tRkIG4P
		// TZH/irTU5K12Y9S3FP/Hx0H8ZyDblDfXMOSGSWbflHgwfZCOg5N/Lb1QSo8mYj8e
		// 32PjTITTBhTQRpqncni+2+vMblUgw/EC1UNQ1mu9qCkGl8415BBVI/Q1qBg7pN1X
		// 1BJsPOwNUZT6SpppWYVc7pfLJ8bS0op7NBx2/401RzGbU9Tdf24UEt72PQ7LHh9n
		// mDBI5JHJ3pOrpKBxfbwKPdSjB6h4mG/V4m1AWp4nnSI0NqOHGqQfxOxhT/GjM+3p
		// 0I2hhVViZ6ApY+XN2WdionaL5TTPcKpcjCJTzhenhWL9psczA9NlkC14o/GOUZ1Y
		// fqIbIUTVOOEAp8YVz9trEI7JSmOoIyDHuS64K4lTSoTIu5rhRk5ngxTQLVYH4FI=
		// -----END CERTIFICATE-----
		// `
		// 				ca1Key := `-----BEGIN EC PRIVATE KEY-----
		// MHcCAQEEIG4qZgKlfDcPcmp8p2XgRrdRezQhI/uZDLSuYAqdTXuzoAoGCCqGSM49
		// AwEHoUQDQgAECl0I78LZEuJTETlQ+v6FtOO13aj2AHsrwHVnEwhnr2qy7gAJDylP
		// CR8nD8fRUZg5Lp5Npew7bufQhTnw8b75zA==
		// -----END EC PRIVATE KEY-----`

		// 				key0, err := chelpers.ParsePrivateKey([]byte(strings.TrimSpace(ca0Key)))
		// 				if err != nil {
		// 					t.Fatalf("could not parse root private key: %s", err)
		// 				}

		// 				key1, err := chelpers.ParsePrivateKey([]byte(strings.Trim(ca1Key, "	")))
		// 				if err != nil {
		// 					t.Fatalf("could not parse ca-lvl-1 private key: %s", err)
		// 				}

		// 				cert0, err := chelpers.ParseCertificate(strings.Trim(ca0Crt, "	"))
		// 				if err != nil {
		// 					t.Fatalf("could not parse root cert: %s", err)
		// 				}

		// 				cert1, err := chelpers.ParseCertificate(strings.Trim(ca1Crt, "	"))
		// 				if err != nil {
		// 					t.Fatalf("could not parse ca-lvl-1 cert: %s", err)
		// 				}

		// 				chelpers.ParsePrivateKey([]byte(ca1Key))
		// 				chelpers.ParsePrivateKey([]byte(ca1Key))

		// 				duration, _ := models.ParseDuration("100d")
		// 				importedRootCA, err := caSDK.ImportCA(context.Background(), services.ImportCAInput{
		// 					CAType: models.CertificateTypeImportedWithKey,
		// 					IssuanceExpiration: models.Validity{
		// 						Type:     models.Duration,
		// 						Duration: (models.TimeDuration)(duration),
		// 					},
		// 					CACertificate: (*models.X509Certificate)(cert0),
		// 					CARSAKey:      (key0).(*rsa.PrivateKey),
		// 					KeyType:       models.KeyType(x509.RSA),
		// 				})
		// 				if err != nil {
		// 					t.Fatalf("could not import root CA: %s", err)
		// 				}

		// 				importedCALvl1, err := caSDK.ImportCA(context.Background(), services.ImportCAInput{
		// 					CAType: models.CertificateTypeImportedWithKey,
		// 					IssuanceExpiration: models.Validity{
		// 						Type:     models.Duration,
		// 						Duration: (models.TimeDuration)(duration),
		// 					},
		// 					CACertificate: (*models.X509Certificate)(cert1),
		// 					CAECKey:       (key1).(*ecdsa.PrivateKey),
		// 					KeyType:       models.KeyType(x509.ECDSA),
		// 					ParentID:      importedRootCA.SubjectKeyID,
		// 				})

		// 				return importedCALvl1, err

		// 			},
		// 			resultCheck: func(ca *models.Certificate, err error) error {
		// 				if err != nil {
		// 					return fmt.Errorf("got unexpected error: %s", err)
		// 				}

		// 				if ca.Level != 1 {
		// 					return fmt.Errorf("CA should be at level 1. Got %d", ca.Level)
		// 				}
		// 				return nil
		// 			},
		// 		},
		{
			name:   "OK/ImportingHierarchyBottomUp",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.Certificate, error) {
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

				importedCALvl2, err := caSDK.ImportCertificate(context.Background(), services.ImportCertificateInput{
					Certificate: cert2,
				})
				if err != nil {
					t.Fatalf("could not import ca-lvl-2 CA: %s", err)
				}

				_, err = caSDK.ImportCertificate(context.Background(), services.ImportCertificateInput{
					Certificate: cert1,
				})
				if err != nil {
					t.Fatalf("could not import ca-lvl-1 CA: %s", err)
				}

				_, err = caSDK.ImportCertificate(context.Background(), services.ImportCertificateInput{
					Certificate: cert0,
				})
				if err != nil {
					t.Fatalf("could not import root CA: %s", err)
				}

				importedCALvl2Updated, err := caSDK.GetCAByID(context.Background(), services.GetCAByIDInput{SubjectKeyID: importedCALvl2.SubjectKeyID})
				if err != nil {
					t.Fatalf("could not retrieve ca-lvl-2 CA: %s", err)
				}

				return importedCALvl2Updated, err
			},
			resultCheck: func(ca *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}

				if ca.Level != 2 {
					return fmt.Errorf("CA should be at level 2. Got %d", ca.Level)
				}

				if ca.IssuerCAMetadata.Level != 1 {
					return fmt.Errorf("CA parent should be at level 1. Got %d", ca.IssuerCAMetadata.Level)
				}

				return nil
			},
		},
		{
			name:   "OK/ImportingHierarchyTopDown",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.Certificate, error) {
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

				_, err = caSDK.ImportCertificate(context.Background(), services.ImportCertificateInput{
					Certificate: cert0,
				})
				if err != nil {
					t.Fatalf("could not import root CA: %s", err)
				}

				_, err = caSDK.ImportCertificate(context.Background(), services.ImportCertificateInput{
					Certificate: cert1,
				})
				if err != nil {
					t.Fatalf("could not import ca-lvl-1 CA: %s", err)
				}

				importedCALvl2, err := caSDK.ImportCertificate(context.Background(), services.ImportCertificateInput{
					Certificate: cert2,
				})
				if err != nil {
					t.Fatalf("could not import ca-lvl-2 CA: %s", err)
				}

				return importedCALvl2, err

			},
			resultCheck: func(ca *models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}

				if ca.Level != 2 {
					return fmt.Errorf("CA should be at level 2. Got %d", ca.Level)
				}

				if ca.IssuerCAMetadata.Level != 1 {
					return fmt.Errorf("CA parent should be at level 1. Got %d", ca.IssuerCAMetadata.Level)
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

	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").Build(t)
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
				//cas := []*models.Certificate{}
				err := caSDK.DeleteCA(context.Background(), services.DeleteCAInput{
					SubjectKeyID: "DefaulasdadtCAID",
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
					SubjectKeyID:     DefaultCAID,
					Status:           models.StatusRevoked,
					RevocationReason: models.RevocationReason(1),
				})

				if err != nil {
					return fmt.Errorf("Error updating the CA status to expired")
				}
				return err

			},
			run: func(caSDK services.CAService) error {
				//cas := []*models.Certificate{}
				err := caSDK.DeleteCA(context.Background(), services.DeleteCAInput{
					SubjectKeyID: DefaultCAID,
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
					SubjectKeyID:     DefaultCAID,
					Status:           models.StatusActive,
					RevocationReason: models.RevocationReason(1),
				})

				if err != nil {
					return fmt.Errorf("Error updating the CA status to expired")
				}
				return err

			},
			run: func(caSDK services.CAService) error {
				//cas := []*models.Certificate{}
				err := caSDK.DeleteCA(context.Background(), services.DeleteCAInput{
					SubjectKeyID: DefaultCAID,
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

func TestGetCAs(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").Build(t)
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
			name: "Err/GetCAsExRunTrue",
			before: func(svc services.CAService) error {

				return nil
			},
			run: func(caSDK services.CAService) ([]*models.Certificate, error) {
				cas := []*models.Certificate{}
				res, err := caSDK.GetCAs(context.Background(), services.GetCAsInput{
					ExhaustiveRun: true,
					ApplyFunc: func(elem models.Certificate) {
						cas = append(cas, &elem)
					},
				})
				fmt.Println(res)
				return cas, err
			},
			resultCheck: func(cas []*models.Certificate, err error) error {
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
				caDUr := models.TimeDuration(time.Hour * 24)
				for i := 0; i < 5; i++ {
					res, _ := svc.CreateCA(context.Background(), services.CreateCAInput{
						KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
						Subject:      models.Subject{CommonName: DefaultCACN},
						CAExpiration: models.Validity{Type: models.Duration, Duration: caDUr},
					})
					fmt.Println(res)
				}

				return nil
			},
			run: func(caSDK services.CAService) ([]*models.Certificate, error) {
				cas := []*models.Certificate{}
				res, err := caSDK.GetCAs(context.Background(), services.GetCAsInput{
					ExhaustiveRun: false,
					ApplyFunc: func(elem models.Certificate) {
						cas = append(cas, &elem)
					},
					QueryParameters: &resources.QueryParameters{
						PageSize: 2,
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
					return fmt.Errorf("should've got only two CAS, but got %d.", len(cas))
				}
				return nil
			},
		},
		{
			name: "Err/GetCAsExRunTrue",
			before: func(svc services.CAService) error {
				caDUr := models.TimeDuration(time.Hour * 24)
				for i := 0; i < 5; i++ {
					res, _ := svc.CreateCA(context.Background(), services.CreateCAInput{
						KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
						Subject:      models.Subject{CommonName: DefaultCACN},
						CAExpiration: models.Validity{Type: models.Duration, Duration: caDUr},
					})
					fmt.Println(res)
				}

				return nil
			},
			run: func(caSDK services.CAService) ([]*models.Certificate, error) {
				cas := []*models.Certificate{}
				res, err := caSDK.GetCAs(context.Background(), services.GetCAsInput{
					ExhaustiveRun: true,
					ApplyFunc: func(elem models.Certificate) {
						cas = append(cas, &elem)
					},
					QueryParameters: &resources.QueryParameters{
						PageSize: 2,
					},
				})
				fmt.Println(res)
				return cas, err
			},
			resultCheck: func(cas []*models.Certificate, err error) error {
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
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA
	issuanceDur := models.TimeDuration(time.Hour * 12)

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
					SubjectKeyID: caID,
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

				_, err = svc.GetCAByID(context.Background(), services.GetCAByIDInput{SubjectKeyID: caID})
				if err != nil {
					return fmt.Errorf("Error getting the CA: %s", err)
				}

				actCSR, _ := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "active-cert"}, actKey)
				_, err = svc.SignCertificate(context.Background(), services.SignCertificateInput{
					SubjectKeyID: caID,
					CertRequest:  (*models.X509CertificateRequest)(actCSR),
					IssuanceProfile: models.IssuanceProfile{
						Validity:        models.Validity{Type: models.Duration, Duration: issuanceDur},
						SignAsCA:        false,
						HonorSubject:    true,
						HonorExtensions: true,
					},
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
					SubjectKeyID: caID,
					CertRequest:  (*models.X509CertificateRequest)(revCSR),
					IssuanceProfile: models.IssuanceProfile{
						Validity:        models.Validity{Type: models.Duration, Duration: issuanceDur},
						SignAsCA:        false,
						HonorSubject:    true,
						HonorExtensions: true,
					},
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
					SubjectKeyID: caID,
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

			rootCA, err := caTest.Service.CreateCA(context.Background(), services.CreateCAInput{
				KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
				Subject:      models.Subject{CommonName: "CA Lvl 1"},
				CAExpiration: models.Validity{Type: models.Duration, Duration: exp},
			})
			if err != nil {
				t.Fatalf("failed creating root CA: %s", err)
			}

			err = tc.before(caTest.Service, rootCA.SubjectKeyID)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(caTest.HttpCASDK, rootCA.SubjectKeyID))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func TestGetCertificatesByExpirationDate(t *testing.T) {
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA
	issuanceDur := models.TimeDuration(time.Hour * 12)

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) ([]*models.Certificate, error)
		resultCheck func([]*models.Certificate, error) error
	}{
		{
			name: "Err/GetCAGertByExpDate",
			before: func(svc services.CAService) error {
				_, err := svc.GetCAByID(context.Background(), services.GetCAByIDInput{SubjectKeyID: DefaultCAID})
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
						SubjectKeyID: DefaultCAID,
						CertRequest:  (*models.X509CertificateRequest)(csr),
						IssuanceProfile: models.IssuanceProfile{
							Validity:        models.Validity{Type: models.Duration, Duration: issuanceDur},
							SignAsCA:        false,
							HonorSubject:    true,
							HonorExtensions: true,
						},
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
				_, err := svc.GetCAByID(context.Background(), services.GetCAByIDInput{SubjectKeyID: DefaultCAID})
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
						SubjectKeyID: DefaultCAID,
						CertRequest:  (*models.X509CertificateRequest)(csr),
						IssuanceProfile: models.IssuanceProfile{
							Validity:        models.Validity{Type: models.Duration, Duration: issuanceDur},
							SignAsCA:        false,
							HonorSubject:    true,
							HonorExtensions: true,
						},
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
				_, err := svc.GetCAByID(context.Background(), services.GetCAByIDInput{SubjectKeyID: DefaultCAID})
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
						SubjectKeyID: DefaultCAID,
						CertRequest:  (*models.X509CertificateRequest)(csr),
						IssuanceProfile: models.IssuanceProfile{
							Validity:        models.Validity{Type: models.Duration, Duration: issuanceDur},
							SignAsCA:        false,
							HonorSubject:    true,
							HonorExtensions: true,
						},
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
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").Build(t)
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
					SubjectKeyID:     DefaultCAID,
					Message:          []byte(messB),
					MessageType:      models.Raw,
					SigningAlgorithm: "RSASSA_PSS_SHA_256",
				})
				if err != nil {
					return false, err
				}

				res, err := caSDK.SignatureVerify(context.Background(), services.SignatureVerifyInput{
					SubjectKeyID:     DefaultCAID,
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
					SubjectKeyID:     DefaultCAID,
					Message:          []byte(messB),
					MessageType:      models.Raw,
					SigningAlgorithm: "RSASSA_PKCS1_V1_5_SHA_384",
				})
				if err != nil {
					return false, err
				}

				res, err := caSDK.SignatureVerify(context.Background(), services.SignatureVerifyInput{
					SubjectKeyID:     DefaultCAID,
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
					SubjectKeyID:     DefaultCAID,
					Message:          []byte(messH),
					MessageType:      models.Hashed,
					SigningAlgorithm: "RSASSA_PSS_SHA_256",
				})
				if err != nil {
					return false, err
				}

				res, err := caSDK.SignatureVerify(context.Background(), services.SignatureVerifyInput{
					SubjectKeyID:     DefaultCAID,
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
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) ([]models.Certificate, error)
		resultCheck func([]models.Certificate, error) error
	}{
		{
			name: "OK/TestHighDurationRootCA",
			before: func(svc services.CAService) error {

				return nil
			},
			run: func(caSDK services.CAService) ([]models.Certificate, error) {
				var cas []models.Certificate
				caDurRootCA := models.TimeDuration(time.Hour * 25)
				caDurChild1 := models.TimeDuration(time.Hour * 24)

				engines, _ := caSDK.GetCryptoEngineProvider(context.Background())

				rootCA, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "CA Lvl 1"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDurRootCA},
					EngineID:     engines[0].ID,
				})

				if err != nil {
					t.Fatalf("failed creating the root CA: %s", err)
				}
				cas = append(cas, *rootCA)

				childCALvl1, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "CA Lvl 1"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDurChild1},
					ParentID:     rootCA.SubjectKeyID,
				})
				if err != nil {
					t.Fatalf("failed creating the first CA child: %s", err)
				}
				cas = append(cas, *childCALvl1)
				fmt.Println("=============================")
				fmt.Println("CN:" + childCALvl1.Subject.CommonName)
				fmt.Println("ID:" + childCALvl1.SubjectKeyID)
				fmt.Println("SN:" + childCALvl1.SerialNumber)
				fmt.Println("=============================")

				//cas := []*models.Certificate{}

				return cas, err
			},
			resultCheck: func(cas []models.Certificate, err error) error {

				rootCa := cas[0]
				childCa := cas[1]

				if rootCa.ValidTo.Before(childCa.ValidTo) {
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
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").Build(t)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) ([]models.Certificate, error)
		resultCheck func([]models.Certificate, error) error
	}{
		{
			name: "OK/TestHighDurationRootCA",
			before: func(svc services.CAService) error {

				return nil
			},
			run: func(caSDK services.CAService) ([]models.Certificate, error) {
				var cas []models.Certificate
				caDurRootCA := models.TimeDuration(time.Hour * 25)
				caDurChild1 := models.TimeDuration(time.Hour * 24)
				caDurChild2 := models.TimeDuration(time.Hour * 23)

				rootCA, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "CA Lvl 0"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDurRootCA},
				})
				if err != nil {
					t.Fatalf("failed creating the root CA: %s", err)
				}

				cas = append(cas, *rootCA)

				childCALvl1, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "CA Lvl 1"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDurChild1},
					ParentID:     rootCA.SubjectKeyID,
				})
				if err != nil {
					t.Fatalf("failed creating the first CA child: %s", err)
				}
				cas = append(cas, *childCALvl1)
				fmt.Println("=============================")
				fmt.Println("CN:" + childCALvl1.Subject.CommonName)
				fmt.Println("ID:" + childCALvl1.SubjectKeyID)
				fmt.Println("SN:" + childCALvl1.SerialNumber)
				fmt.Println("SKID:" + childCALvl1.SubjectKeyID)
				fmt.Println("AKID:" + childCALvl1.AuthorityKeyID)
				fmt.Println("Type:" + childCALvl1.Type)
				fmt.Println("=============================")

				childCALvl2, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "CA Lvl 2"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDurChild2},
					ParentID:     childCALvl1.SubjectKeyID,
				})
				if err != nil {
					t.Fatalf("failed creating the second CA child: %s", err)
				}

				fmt.Println("=============================")
				fmt.Println("CN:" + childCALvl2.Subject.CommonName)
				fmt.Println("ID:" + childCALvl2.SubjectKeyID)
				fmt.Println("SN:" + childCALvl2.SerialNumber)
				fmt.Println("=============================")

				//cas := []*models.Certificate{}

				return cas, err
			},
			resultCheck: func(cas []models.Certificate, err error) error {
				rootCa := cas[0]
				childCa := cas[1]

				if rootCa.ValidTo.Before(childCa.ValidTo) {
					return fmt.Errorf("requested CA would expire after parent CA")
				}

				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}

				return nil
			},
		},
		{
			name: "ERR/ChildCAExpiresAfterRootCA",
			before: func(svc services.CAService) error {
				return nil
			},
			run: func(caSDK services.CAService) ([]models.Certificate, error) {
				var cas []models.Certificate
				caDurChild1 := models.TimeDuration(time.Hour * 26)
				caDurRootCA := models.TimeDuration(time.Hour * 25)

				rootCA, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "CA Lvl 0"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDurRootCA},
				})

				if err != nil {
					t.Fatalf("failed creating the root CA: %s", err)
				}

				cas = append(cas, *rootCA)
				_, err = caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "CA Lvl 1"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDurChild1},
					ParentID:     rootCA.SubjectKeyID,
				})

				//cas := []*models.Certificate{}

				return cas, err
			},
			resultCheck: func(cas []models.Certificate, err error) error {
				if err == nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}

				return nil
			},
		},
		{
			name: "OK/TestHightDateLimitRootCA",
			before: func(svc services.CAService) error {

				return nil
			},
			run: func(caSDK services.CAService) ([]models.Certificate, error) {
				var cas []models.Certificate
				caRDLim := time.Date(3000, 12, 1, 0, 0, 0, 0, time.Local)   // expires the 1st of december of 3000
				caCDLim1 := time.Date(3000, 11, 28, 0, 0, 0, 0, time.Local) // expires the 28th of november of 3000
				caCDLim2 := time.Date(3000, 11, 27, 0, 0, 0, 0, time.Local) // expires the 27 of november of 3000

				ca, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: DefaultCACN},
					CAExpiration: models.Validity{Type: models.Time, Time: caRDLim},
				})
				if err != nil {
					t.Fatalf("failed creating the first CA child: %s", err)
				}
				cas = append(cas, *ca)

				fmt.Println("=============================")
				fmt.Println("CN:" + ca.Subject.CommonName)
				fmt.Println("ID:" + ca.SubjectKeyID)
				fmt.Println("SN:" + ca.SerialNumber)
				fmt.Println("=============================")

				childCALvl1, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "CA Lvl 1"},
					CAExpiration: models.Validity{Type: models.Time, Time: caCDLim1},
					ParentID:     ca.SubjectKeyID,
				})
				if err != nil {
					t.Fatalf("failed creating the first CA child: %s", err)
				}
				cas = append(cas, *childCALvl1)
				fmt.Println("=============================")
				fmt.Println("CN:" + childCALvl1.Subject.CommonName)
				fmt.Println("ID:" + childCALvl1.SubjectKeyID)
				fmt.Println("SN:" + childCALvl1.SerialNumber)
				fmt.Println("=============================")

				childCALvl2, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "CA Lvl 1"},
					CAExpiration: models.Validity{Type: models.Time, Time: caCDLim2},
					ParentID:     childCALvl1.SubjectKeyID,
				})
				if err != nil {
					t.Fatalf("failed creating the first CA child: %s", err)
				}

				fmt.Println("=============================")
				fmt.Println("CN:" + childCALvl2.Subject.CommonName)
				fmt.Println("ID:" + childCALvl2.SubjectKeyID)
				fmt.Println("SN:" + childCALvl2.SerialNumber)
				fmt.Println("=============================")

				//cas := []*models.Certificate{}

				return cas, err
			},
			resultCheck: func(cas []models.Certificate, err error) error {
				rootCa := cas[0]
				childCa := cas[1]

				if rootCa.ValidTo.Before(childCa.ValidTo) {
					return fmt.Errorf("requested CA would expire after parent CA")
				}

				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}

				return nil
			},
		},
		{
			name: "ERR/ChildCAExpiresAfterParentCA-UsingFixedDates",
			before: func(svc services.CAService) error {
				return nil
			},
			run: func(caSDK services.CAService) ([]models.Certificate, error) {
				var cas []models.Certificate
				caRDLim := time.Date(2030, 12, 1, 0, 0, 0, 0, time.Local)
				caCDLim1 := time.Date(2030, 12, 2, 0, 0, 0, 0, time.Local)

				ca, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: DefaultCACN},
					CAExpiration: models.Validity{Type: models.Time, Time: caRDLim},
				})

				if err != nil {
					return nil, err
				}

				cas = append(cas, *ca)
				_, err = caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "CA Lvl 1"},
					CAExpiration: models.Validity{Type: models.Time, Time: caCDLim1},
					ParentID:     ca.SubjectKeyID,
				})

				//cas := []*models.Certificate{}

				return cas, err
			},
			resultCheck: func(cas []models.Certificate, err error) error {

				if err == nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}

				return nil
			},
		},
		{
			name: "OK/TestMixedExpirationTimeFormats",
			before: func(svc services.CAService) error {
				return nil
			},
			run: func(caSDK services.CAService) ([]models.Certificate, error) {
				var cas []models.Certificate
				caRDLim := time.Date(3000, 12, 1, 0, 0, 0, 0, time.Local)
				caDurChild1 := models.TimeDuration(time.Hour * 26)

				ca, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: DefaultCACN},
					CAExpiration: models.Validity{Type: models.Time, Time: caRDLim},
				})

				if err != nil {
					return nil, err
				}

				cas = append(cas, *ca)

				childCALvl1, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:      models.Subject{CommonName: "CA Lvl 1"},
					CAExpiration: models.Validity{Type: models.Duration, Duration: caDurChild1},
					ParentID:     ca.SubjectKeyID,
				})
				cas = append(cas, *childCALvl1)

				return cas, err
			},
			resultCheck: func(cas []models.Certificate, err error) error {

				rootCa := cas[0]
				childCa := cas[1]

				if rootCa.ValidTo.Before(childCa.ValidTo) {
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
	serverTest, err := TestServiceBuilder{}.WithDatabase("ca").WithMonitor().Build(t)
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

			ca, err := serverTest.CA.Service.CreateCA(context.Background(), services.CreateCAInput{
				KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256},
				Subject:      models.Subject{CommonName: "MyCA"},
				CAExpiration: models.Validity{Type: models.Duration, Duration: caDur},
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

				caExpFromNow := ca.ValidTo.Sub(now)
				updatedCA, err := serverTest.CA.Service.GetCAByID(context.Background(), services.GetCAByIDInput{SubjectKeyID: ca.SubjectKeyID})
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

func initCA(caSDK services.CAService) (*models.Certificate, error) {
	caDUr := models.TimeDuration(time.Hour * 25)
	ca, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:      models.Subject{CommonName: DefaultCACN},
		CAExpiration: models.Validity{Type: models.Duration, Duration: caDUr},
	})
	DefaultCAID = ca.SubjectKeyID
	return ca, err
}
