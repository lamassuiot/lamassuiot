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
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v2/pkg/clients"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage/postgres"
	vault_test "github.com/lamassuiot/lamassuiot/v2/pkg/test/subsystems/cryptoengines/keyvaultkv2"
	postgres_test "github.com/lamassuiot/lamassuiot/v2/pkg/test/subsystems/storage/postgres"
	"golang.org/x/crypto/ocsp"
)

const DefaultCAID = "111111-2222"
const DefaultCACN = "MyCA"

func TestCryptoEngines(t *testing.T) {
	caTest, err := BuildCATestServer()
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	t.Cleanup(caTest.AfterSuite)

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

			err = caTest.BeforeEach()
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
	caTest, err := BuildCATestServer()
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	t.Cleanup(caTest.AfterSuite)

	caID := "12345-11111"
	caDUr := models.TimeDuration(time.Hour * 24)
	issuanceDur := models.TimeDuration(time.Hour * 12)

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
					ID:                 caID,
					KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:            models.Subject{CommonName: "TestCA"},
					CAExpiration:       models.Expiration{Type: models.Duration, Duration: &caDUr},
					IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: &issuanceDur},
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
					ID:                 caID,
					KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256},
					Subject:            models.Subject{CommonName: "TestCA"},
					CAExpiration:       models.Expiration{Type: models.Duration, Duration: &caDUr},
					IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: &issuanceDur},
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
					ID:                 caID,
					KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:            models.Subject{CommonName: "TestCA"},
					CAExpiration:       models.Expiration{Type: models.Duration, Duration: &caDUr},
					IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: &issuanceDur},
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
				return caSDK.CreateCA(context.Background(), services.CreateCAInput{
					ID:                 caID,
					KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:            models.Subject{CommonName: "TestCA"},
					CAExpiration:       models.Expiration{Type: models.Time, Time: &tCA},
					IssuanceExpiration: models.Expiration{Type: models.Time, Time: &tIssue},
				})
			},
			resultCheck: func(createdCA *models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've created CA without error, but got error: %s", err)
				}

				if createdCA.ValidTo.Year() != 9999 {
					t.Fatalf("CA certificate should expire on 9999 but got %d", createdCA.ValidTo.Year())
				}

				return nil
			},
		},
		{
			name: "Error/Duplicate-CA-ID",
			before: func(svc services.CAService) error {
				_, err := svc.CreateCA(context.Background(), services.CreateCAInput{
					ID:                 caID,
					KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:            models.Subject{CommonName: "TestCA"},
					CAExpiration:       models.Expiration{Type: models.Duration, Duration: &caDUr},
					IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: &issuanceDur},
				})
				if err != nil {
					return err
				}
				return nil
			},
			run: func(caSDK services.CAService) (*models.CACertificate, error) {
				return caSDK.CreateCA(context.Background(), services.CreateCAInput{
					ID:                 caID,
					KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:            models.Subject{CommonName: "TestCA"},
					CAExpiration:       models.Expiration{Type: models.Duration, Duration: &caDUr},
					IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: &issuanceDur},
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

			err = caTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' func in test case: %s", err)
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
func TestGetCertificatesByCaAndStatus(t *testing.T) {
	caTest, err := BuildCATestServer()
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	t.Cleanup(caTest.AfterSuite)
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
				for i := 0; i < certsToIssue; i++ {
					key, err := helpers.GenerateRSAKey(2048)
					if err != nil {
						return fmt.Errorf("Error creating the private key: %s", err)
					}
					csr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: fmt.Sprintf("cert-%d", i)}, key)
					_, err = svc.SignCertificate(context.Background(), services.SignCertificateInput{CAID: DefaultCAID, SignVerbatim: true, CertRequest: (*models.X509CertificateRequest)(csr)})
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
				certsToIssue := 15
				for i := 0; i < certsToIssue; i++ {
					key, _ := helpers.GenerateRSAKey(2048)
					csr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: fmt.Sprintf("cert-%d", i)}, key)
					_, err := svc.SignCertificate(context.Background(), services.SignCertificateInput{CAID: DefaultCAID, SignVerbatim: true, CertRequest: (*models.X509CertificateRequest)(csr)})
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

				if len(certs) != 15 {
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
			err = caTest.BeforeEach()
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
func TestRevokeCA(t *testing.T) {
	caTest, err := BuildCATestServer()
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	t.Cleanup(caTest.AfterSuite)

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
			run: func(caSDK services.CAService) (*models.CACertificate, error) {
				issue20 := 20
				for i := 0; i < issue20; i++ {
					key, err := helpers.GenerateRSAKey(2048)
					if err != nil {
						return nil, err
					}

					csr, err := helpers.GenerateCertificateRequest(models.Subject{CommonName: fmt.Sprintf("test-%d", i)}, key)
					if err != nil {
						return nil, err
					}

					caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
						CAID:         DefaultCAID,
						CertRequest:  (*models.X509CertificateRequest)(csr),
						SignVerbatim: true,
					})
				}
				caSDK.SignCertificate(context.Background(), services.SignCertificateInput{
					CAID: DefaultCAID,
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
			err = caTest.BeforeEach()
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
	caTest, err := BuildCATestServer()
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	t.Cleanup(caTest.AfterSuite)
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
				ud["userName"] = "noob"
				//cas := []*models.CACertificate{}
				_, err := caSDK.UpdateCAMetadata(context.Background(), services.UpdateCAMetadataInput{
					CAID:     DefaultCAID,
					Metadata: ud,
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
				ud["userName"] = "noob"
				//cas := []*models.CACertificate{}
				_, err := caSDK.UpdateCAMetadata(context.Background(), services.UpdateCAMetadataInput{
					CAID:     "sdfsfgsd",
					Metadata: ud,
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

			err = caTest.BeforeEach()
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
	caTest, err := BuildCATestServer()
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	t.Cleanup(caTest.AfterSuite)

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

			err = caTest.BeforeEach()
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
	caTest, err := BuildCATestServer()
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	t.Cleanup(caTest.AfterSuite)

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

				key, err := helpers.GenerateRSAKey(2048)
				if err != nil {
					return fmt.Errorf("Error creating the private key: %s", err)
				}

				csr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: fmt.Sprintf("cert-%d", 1)}, key)
				cert, err := caSDK.SignCertificate(context.Background(), services.SignCertificateInput{CAID: DefaultCAID, SignVerbatim: true, CertRequest: (*models.X509CertificateRequest)(csr)})
				if err != nil {
					return err
				}
				ud := make(map[string]interface{})
				ud["userName"] = "noob"
				_, err = caSDK.UpdateCertificateMetadata(context.Background(), services.UpdateCertificateMetadataInput{
					SerialNumber: cert.SerialNumber,
					Metadata:     ud,
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
				ud["userName"] = "noob"
				_, err = caSDK.UpdateCertificateMetadata(context.Background(), services.UpdateCertificateMetadataInput{
					SerialNumber: "dadaafgsdtw",
					Metadata:     ud,
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
				ud["userName"] = "noob"
				_, err = caSDK.UpdateCertificateMetadata(context.Background(), services.UpdateCertificateMetadataInput{
					SerialNumber: "dadaafgsdtw",
					Metadata:     nil,
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

			err = caTest.BeforeEach()
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
	caTest, err := BuildCATestServer()
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	t.Cleanup(caTest.AfterSuite)
	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) (*models.CACertificate, error)
		resultCheck func(*models.CACertificate, error) error
	}{
		{
			name:   "OK/UpdateCAStatusExp",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.CACertificate, error) {
				caStatus := models.StatusExpired
				res, err := caSDK.UpdateCAStatus(context.Background(), services.UpdateCAStatusInput{
					CAID:             DefaultCAID,
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
				if ca.Status != caStatus {
					return nil, fmt.Errorf("The updating process does not gone well")
				}
				return res, err
			},
			resultCheck: func(cas *models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've got the process without error, but got error: %s", err)
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
				if ca.Status != caStatus {
					return nil, fmt.Errorf("The updating process does not gone well")
				}
				return res, err
			},
			resultCheck: func(cas *models.CACertificate, err error) error {
				if err == nil {
					return fmt.Errorf("should've got the process with error, but did not get error: %s", err)
				}
				return nil
			},
		},
		{
			name:   "OK/UpdateCAStatusRevo",
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
					return nil, fmt.Errorf("Got error while updating the status of the CA %s", err)
				}

				ca, err := caSDK.GetCAByID(context.Background(), services.GetCAByIDInput{
					CAID: DefaultCAID,
				})
				if err != nil {
					return nil, fmt.Errorf("Got error while checking the status of the CA %s", err)
				}
				if ca.Status != caStatus {
					return nil, fmt.Errorf("The updating process does not gone well")
				}
				return res, err
			},
			resultCheck: func(cas *models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've got the process without error, but got error: %s", err)
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

			err = caTest.BeforeEach()
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
	caTest, err := BuildCATestServer()
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	t.Cleanup(caTest.AfterSuite)
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

			err = caTest.BeforeEach()
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
	caTest, err := BuildCATestServer()
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	t.Cleanup(caTest.AfterSuite)
	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) ([]*models.Certificate, error)
		resultCheck func([]*models.Certificate, error) error
	}{
		{
			name: "OK/GetsCertificatesEXRunTrue",
			before: func(svc services.CAService) error {

				for i := 0; i < 20; i++ {
					key, err := helpers.GenerateRSAKey(2048)
					if err != nil {
						return fmt.Errorf("Error creating the private key: %s", err)
					}

					csr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: fmt.Sprintf("cert-%d", 1)}, key)
					_, err = svc.SignCertificate(context.Background(), services.SignCertificateInput{CAID: DefaultCAID, SignVerbatim: true, CertRequest: (*models.X509CertificateRequest)(csr)})
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
				if len(certs) != 20 {
					return fmt.Errorf("should've got 20 certificates, the content of the all files: %s", err)
				}
				if err != nil {
					return fmt.Errorf("should've got the certificates without error, but got error: %s", err)
				}
				return nil
			},
		},
		{
			name: "OK/GetsCertificatesEXRunFalse",
			before: func(svc services.CAService) error {

				for i := 0; i < 20; i++ {
					key, err := helpers.GenerateRSAKey(2048)
					if err != nil {
						return fmt.Errorf("Error creating the private key: %s", err)
					}

					csr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: fmt.Sprintf("cert-%d", 1)}, key)
					_, err = svc.SignCertificate(context.Background(), services.SignCertificateInput{CAID: DefaultCAID, SignVerbatim: true, CertRequest: (*models.X509CertificateRequest)(csr)})
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

				if len(certs) != 5 {
					return fmt.Errorf("should've got 5 certificates, the content of the first page: %s", err)
				}
				if err != nil {
					return fmt.Errorf("should've got the certificates without error, but got error: %s", err)
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

			err = caTest.BeforeEach()
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
	caTest, err := BuildCATestServer()
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	t.Cleanup(caTest.AfterSuite)
	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) ([]*models.Certificate, error)
		resultCheck func([]*models.Certificate, error) error
	}{
		{
			name: "OK/GetCertificatesByCAExRunFalse",
			before: func(svc services.CAService) error {

				for i := 0; i < 20; i++ {
					key, err := helpers.GenerateRSAKey(2048)
					if err != nil {
						return fmt.Errorf("Error creating the private key: %s", err)
					}

					csr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: fmt.Sprintf("cert-%d", 1)}, key)
					_, err = svc.SignCertificate(context.Background(), services.SignCertificateInput{CAID: DefaultCAID, SignVerbatim: true, CertRequest: (*models.X509CertificateRequest)(csr)})
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
				if len(certs) != 5 {
					return fmt.Errorf("should've got 20 certificates, the content of the all files: %s", err)
				}
				if err != nil {
					return fmt.Errorf("should've got the certificates without error, but got error: %s", err)
				}
				return nil
			},
		},
		{
			name: "OK/GetCertificatesByCAExRunTrue",
			before: func(svc services.CAService) error {

				for i := 0; i < 20; i++ {
					key, err := helpers.GenerateRSAKey(2048)
					if err != nil {
						return fmt.Errorf("Error creating the private key: %s", err)
					}

					csr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: fmt.Sprintf("cert-%d", 1)}, key)
					_, err = svc.SignCertificate(context.Background(), services.SignCertificateInput{CAID: DefaultCAID, SignVerbatim: true, CertRequest: (*models.X509CertificateRequest)(csr)})
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
				if len(certs) != 20 {
					return fmt.Errorf("should've got 20 certificates, the content of the all files: %s", err)
				}
				if err != nil {
					return fmt.Errorf("should've got the certificates without error, but got error: %s", err)
				}
				return nil
			},
		},
		{
			name: "OK/GetCertificatesByCANotExistERunFalse",
			before: func(svc services.CAService) error {

				for i := 0; i < 20; i++ {
					key, err := helpers.GenerateRSAKey(2048)
					if err != nil {
						return fmt.Errorf("Error creating the private key: %s", err)
					}

					csr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: fmt.Sprintf("cert-%d", 1)}, key)
					_, err = svc.SignCertificate(context.Background(), services.SignCertificateInput{CAID: DefaultCAID, SignVerbatim: true, CertRequest: (*models.X509CertificateRequest)(csr)})
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
					CAID: "manex",
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

				for i := 0; i < 20; i++ {
					key, err := helpers.GenerateRSAKey(2048)
					if err != nil {
						return fmt.Errorf("Error creating the private key: %s", err)
					}

					csr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: fmt.Sprintf("cert-%d", 1)}, key)
					_, err = svc.SignCertificate(context.Background(), services.SignCertificateInput{CAID: DefaultCAID, SignVerbatim: true, CertRequest: (*models.X509CertificateRequest)(csr)})
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
					CAID: "manex",
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

			err = caTest.BeforeEach()
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

	caTest, err := BuildCATestServer()
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	t.Cleanup(caTest.AfterSuite)

	generateSelfSignedCA := func(keyType x509.PublicKeyAlgorithm) (*x509.Certificate, any, error) {
		var err error
		var key any
		var pubKey any

		switch keyType {
		case x509.RSA:
			rsaKey, err := helpers.GenerateRSAKey(2048)
			if err != nil {
				return nil, nil, err
			}
			key = rsaKey
			pubKey = &rsaKey.PublicKey
		case x509.ECDSA:
			eccKey, err := helpers.GenerateECDSAKey(elliptic.P224())
			if err != nil {
				return nil, nil, err
			}
			key = eccKey
			pubKey = &eccKey.PublicKey
		}

		if err != nil {
			return nil, nil, err
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
		run         func(caSDK services.CAService) (*models.CAStats, error)
		resultCheck func(*models.CAStats, error) error
	}{
		{
			name:   "OK/ImportingExternalCA",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.CAStats, error) {
				ca, _, err := generateSelfSignedCA(x509.RSA)
				var duration time.Duration = 100
				if err != nil {
					return nil, fmt.Errorf("Failed creating the certificate %s", err)
				}
				_, err = caSDK.ImportCA(context.Background(), services.ImportCAInput{
					ID:     "c1acdb823dd8ac113d2b0a1aaa03e6abf45b4d24e0bf7d8adef322c06987baca",
					CAType: models.CertificateTypeExternal,
					IssuanceExpiration: models.Expiration{
						Type:     models.Duration,
						Duration: (*models.TimeDuration)(&duration),
					},
					CACertificate: (*models.X509Certificate)(ca),

					//Here are missing a lot of parameterss
				})
				if err != nil {
					return nil, fmt.Errorf("Failed importing the new CA to Lamassu %s", err)
				}
				return nil, err
			},
			resultCheck: func(cas *models.CAStats, err error) error {
				if err != nil {
					return fmt.Errorf("should have gone correct, but got an error: %s", err)
				}

				return nil
			},
		},
		{
			name:   "OK/ImportingImportedCA",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.CAStats, error) {
				ca, key, err := generateSelfSignedCA(x509.RSA)
				var duration time.Duration = 100
				if err != nil {
					return nil, fmt.Errorf("Failed creating the certificate %s", err)
				}
				_, err = caSDK.ImportCA(context.Background(), services.ImportCAInput{
					ID:     "c1acdb823dd8ac113d2b0a1aaa03e6a4e0bf7d8adef322c06987baca",
					CAType: models.CertificateTypeImportedWithKey,
					IssuanceExpiration: models.Expiration{
						Type:     models.Duration,
						Duration: (*models.TimeDuration)(&duration),
					},
					CACertificate: (*models.X509Certificate)(ca),
					CARSAKey:      (key).(*rsa.PrivateKey),
					KeyType:       models.KeyType(x509.RSA),
					//Here are missing a lot of parameterss
				})
				if err != nil {
					return nil, fmt.Errorf("Failed importing the new CA to Lamassu %s", err)
				}
				return nil, err
			},
			resultCheck: func(cas *models.CAStats, err error) error {
				if err != nil {
					return fmt.Errorf("should have gone correct, but got an error: %s", err)
				}
				return nil
			},
		},
		{
			name:   "Err_InputVal/ImportingImporteEngineID",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.CAStats, error) {
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

				_, err = caSDK.ImportCA(context.Background(), services.ImportCAInput{
					ID:     "c1acdb823dd8ac113d2b0a1aaa03e6a4e0bf7d8adef322c06987baca",
					CAType: models.CertificateTypeImportedWithKey,
					IssuanceExpiration: models.Expiration{
						Type:     models.Duration,
						Duration: (*models.TimeDuration)(&duration),
					},
					CACertificate: (*models.X509Certificate)(ca),
					CARSAKey:      (key).(*rsa.PrivateKey),
					KeyType:       models.KeyType(x509.RSA),
					EngineID:      engine.ID,

					//Here are missing a lot of parameterss
				})

				if err != nil {
					return nil, fmt.Errorf("Failed importing the new CA to Lamassu %s", err)
				}
				return nil, err
			},
			resultCheck: func(cas *models.CAStats, err error) error {
				if err != nil {
					return fmt.Errorf("should have gone correct, but got an error: %s", err)
				}
				return nil
			},
		},
		{
			name:   "OK/ImportingImportedECDSACA",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.CAStats, error) {
				ca, key, err := generateSelfSignedCA(x509.ECDSA)
				var duration time.Duration = 100
				if err != nil {
					return nil, fmt.Errorf("Failed creating the certificate %s", err)
				}
				_, err = caSDK.ImportCA(context.Background(), services.ImportCAInput{
					ID:     "c1acdb823dd8ac113d2b0a1aaa0adef322c06987baca",
					CAType: models.CertificateTypeImportedWithKey,
					IssuanceExpiration: models.Expiration{
						Type:     models.Duration,
						Duration: (*models.TimeDuration)(&duration),
					},
					CACertificate: (*models.X509Certificate)(ca),
					CAECKey:       (key).(*ecdsa.PrivateKey),
					KeyType:       models.KeyType(x509.ECDSA),
					//Here are missing a lot of parameterss
				})
				if err != nil {
					return nil, fmt.Errorf("Failed importing the new CA to Lamassu %s", err)
				}
				return nil, err
			},
			resultCheck: func(cas *models.CAStats, err error) error {
				if err != nil {
					return fmt.Errorf("should have gone correct, but got an error: %s", err)
				}
				return nil
			},
		},
		{
			name:   "OK/ImportingImportedCAWithoutId",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.CAStats, error) {
				ca, key, err := generateSelfSignedCA(x509.RSA)
				var duration time.Duration = 100
				if err != nil {
					return nil, fmt.Errorf("Failed creating the certificate %s", err)
				}
				_, err = caSDK.ImportCA(context.Background(), services.ImportCAInput{
					CAType: models.CertificateTypeImportedWithKey,
					IssuanceExpiration: models.Expiration{
						Type:     models.Duration,
						Duration: (*models.TimeDuration)(&duration),
					},
					CACertificate: (*models.X509Certificate)(ca),
					CARSAKey:      (key).(*rsa.PrivateKey),
					KeyType:       models.KeyType(x509.RSA),
					//Here are missing a lot of parameterss
				})
				if err != nil {
					return nil, fmt.Errorf("Failed importing the new CA to Lamassu %s", err)
				}
				return nil, err
			},
			resultCheck: func(cas *models.CAStats, err error) error {
				if err != nil {
					return fmt.Errorf("should have gone correct, but got an error: %s", err)
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

			err = caTest.BeforeEach()
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

	caTest, err := BuildCATestServer()
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	t.Cleanup(caTest.AfterSuite)
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
					CAID: "DefaulasdadtCAID",
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
					CAID: DefaultCAID,
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
					CAID: DefaultCAID,
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

			err = caTest.BeforeEach()
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

	caTest, err := BuildCATestServer()
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	t.Cleanup(caTest.AfterSuite)
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
					return fmt.Errorf("should've gone correctly, but got error.")
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
				for i := 0; i < 5; i++ {
					caName = DefaultCAID + strconv.Itoa(i)
					res, _ := svc.CreateCA(context.Background(), services.CreateCAInput{
						ID:                 caName,
						KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
						Subject:            models.Subject{CommonName: DefaultCACN},
						CAExpiration:       models.Expiration{Type: models.Duration, Duration: &caDUr},
						IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: &issuanceDur},
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
					return fmt.Errorf("should've gone correctly, but got error.")
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
				for i := 0; i < 5; i++ {
					caName = DefaultCAID + strconv.Itoa(i)
					res, _ := svc.CreateCA(context.Background(), services.CreateCAInput{
						ID:                 caName,
						KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
						Subject:            models.Subject{CommonName: DefaultCACN},
						CAExpiration:       models.Expiration{Type: models.Duration, Duration: &caDUr},
						IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: &issuanceDur},
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
					return fmt.Errorf("should've gone correctly, but got error.")
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

			err = caTest.BeforeEach()
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

func TestGetCertificatesByExpirationDate(t *testing.T) {

	caTest, err := BuildCATestServer()
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	t.Cleanup(caTest.AfterSuite)
	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) ([]*models.Certificate, error)
		resultCheck func([]*models.Certificate, error) error
	}{
		{
			name: "Err/GetCAGertByExpDate",
			before: func(svc services.CAService) error {
				for i := 0; i < 20; i++ {
					key, err := helpers.GenerateRSAKey(2048)
					if err != nil {
						return fmt.Errorf("Error creating the private key: %s", err)
					}

					csr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: fmt.Sprintf("cert-%d", 1)}, key)
					_, err = svc.SignCertificate(context.Background(), services.SignCertificateInput{CAID: DefaultCAID, SignVerbatim: true, CertRequest: (*models.X509CertificateRequest)(csr)})
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
					ExpiresBefore: time.Date(2025, 0, 0, 0, 0, 0, 0, time.UTC),
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
					return fmt.Errorf("should've gone correctly, but got error.")
				}
				if len(cas) != 20 {
					return fmt.Errorf("should've got only one CA and the received quantity is different.")
				}
				return nil
			},
		},
		{
			name: "Err/GetCAGertByExpDateExhaustiveRun",
			before: func(svc services.CAService) error {
				for i := 0; i < 20; i++ {
					key, err := helpers.GenerateRSAKey(2048)
					if err != nil {
						return fmt.Errorf("Error creating the private key: %s", err)
					}

					csr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: fmt.Sprintf("cert-%d", 1)}, key)
					_, err = svc.SignCertificate(context.Background(), services.SignCertificateInput{CAID: DefaultCAID, SignVerbatim: true, CertRequest: (*models.X509CertificateRequest)(csr)})
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
					ExpiresBefore: time.Date(2025, 0, 0, 0, 0, 0, 0, time.UTC),
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
					return fmt.Errorf("should've gone correctly, but got error.")
				}
				if len(cas) != 2 {
					return fmt.Errorf("should've got only one CA and the received quantity is different.")
				}
				return nil
			},
		},
		{
			name: "Err/GetCAGertByExpDateIncDate",
			before: func(svc services.CAService) error {
				for i := 0; i < 20; i++ {
					key, err := helpers.GenerateRSAKey(2048)
					if err != nil {
						return fmt.Errorf("Error creating the private key: %s", err)
					}

					csr, _ := helpers.GenerateCertificateRequest(models.Subject{CommonName: fmt.Sprintf("cert-%d", 1)}, key)
					_, err = svc.SignCertificate(context.Background(), services.SignCertificateInput{CAID: DefaultCAID, SignVerbatim: true, CertRequest: (*models.X509CertificateRequest)(csr)})
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
					return fmt.Errorf("should've gone correctly, but got error.")
				}
				if len(cas) != 0 {
					return fmt.Errorf("should've got only one CA and the received quantity is different.")
				}
				return nil
			},
		},
	}

	for _, tc := range testcases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {

			err = caTest.BeforeEach()
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
	t.Skip("Skip until we have a reliable test for this")
	caTest, err := BuildCATestServer()
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	t.Cleanup(caTest.AfterSuite)
	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) (bool, error)
		resultCheck func(bool, error) error
	}{
		{
			name:   "OK/TestSignatureVerifyPlainMes",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (bool, error) {

				mess := "manex"
				messB := []byte(mess)
				messba64 := base64.StdEncoding.EncodeToString(messB)
				sign, err := caSDK.SignatureSign(context.Background(), services.SignatureSignInput{
					CAID:             DefaultCAID,
					Message:          []byte(messba64),
					MessageType:      models.Raw,
					SigningAlgorithm: "RSASSA_PSS_SHA_256",
				})

				if err != nil {
					return false, err
				}
				//cas := []*models.CACertificate{}
				res, err := caSDK.SignatureVerify(context.Background(), services.SignatureVerifyInput{
					CAID:             DefaultCAID,
					Signature:        sign,
					SigningAlgorithm: "RSASSA_PSS_SHA_512",
					MessageType:      models.Raw,
					Message:          []byte(messba64),
				})
				return res, err
			},
			resultCheck: func(bol bool, err error) error {
				fmt.Println(bol)
				if !errors.Is(err, errs.ErrCAStatus) {
					return fmt.Errorf("got unexpected error: %s", err)
				}
				return nil
			},
		},
		{
			name:   "OK/TestSignatureVerifyHashMes",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (bool, error) {
				h := sha256.New()
				mess := "manex"
				messB := []byte(mess)
				h.Write([]byte(messB))
				messH := h.Sum(nil)
				messba64 := base64.StdEncoding.EncodeToString(messH)
				sign, err := caSDK.SignatureSign(context.Background(), services.SignatureSignInput{
					CAID:             DefaultCAID,
					Message:          []byte(messba64),
					MessageType:      models.Raw,
					SigningAlgorithm: "RSASSA_PSS_SHA_256",
				})

				if err != nil {
					return false, err
				}

				//cas := []*models.CACertificate{}
				res, err := caSDK.SignatureVerify(context.Background(), services.SignatureVerifyInput{
					CAID:             DefaultCAID,
					Signature:        sign,
					SigningAlgorithm: "RSASSA_PSS_SHA_512",
					MessageType:      models.Raw,
					Message:          []byte(messba64),
				})
				return res, err
			},
			resultCheck: func(bol bool, err error) error {
				fmt.Println(bol)
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
			//
			// err := postgres_test.BeforeEach()
			// fmt.Errorf("Error while running BeforeEach job: %s", err)

			err = caTest.BeforeEach()
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
	caTest, err := BuildCATestServer()
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	t.Cleanup(caTest.AfterSuite)
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

				rootCA, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:            models.Subject{CommonName: "CA Lvl 1"},
					CAExpiration:       models.Expiration{Type: models.Duration, Duration: &caDurRootCA},
					IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: &caIss},
					EngineID:           engines[0].ID,
				})

				if err != nil {
					t.Fatalf("failed creating the root CA: %s", err)
				}
				cas = append(cas, *rootCA)

				childCALvl1, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:            models.Subject{CommonName: "CA Lvl 1"},
					CAExpiration:       models.Expiration{Type: models.Duration, Duration: &caDurChild1},
					IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: &caIss},
					ParentID:           rootCA.ID,
				})
				if err != nil {
					t.Fatalf("failed creating the first CA child: %s", err)
				}
				cas = append(cas, *childCALvl1)
				fmt.Println("=============================")
				fmt.Println("CN:" + childCALvl1.Subject.CommonName)
				fmt.Println("ID:" + childCALvl1.ID)
				fmt.Println("SN:" + childCALvl1.SerialNumber)
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

			err = caTest.BeforeEach()
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
	caTest, err := BuildCATestServer()
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	t.Cleanup(caTest.AfterSuite)
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

				rootCA, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:            models.Subject{CommonName: "CA Lvl 1"},
					CAExpiration:       models.Expiration{Type: models.Duration, Duration: &caDurRootCA},
					IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: &caIss},
				})

				if err != nil {
					t.Fatalf("failed creating the root CA: %s", err)
				}
				cas = append(cas, *rootCA)

				childCALvl1, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:            models.Subject{CommonName: "CA Lvl 1"},
					CAExpiration:       models.Expiration{Type: models.Duration, Duration: &caDurChild1},
					IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: &caIss},
					ParentID:           rootCA.ID,
				})
				if err != nil {
					t.Fatalf("failed creating the first CA child: %s", err)
				}
				cas = append(cas, *childCALvl1)
				fmt.Println("=============================")
				fmt.Println("CN:" + childCALvl1.Subject.CommonName)
				fmt.Println("ID:" + childCALvl1.ID)
				fmt.Println("SN:" + childCALvl1.SerialNumber)
				fmt.Println("=============================")

				childCALvl2, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:            models.Subject{CommonName: "CA Lvl 2"},
					CAExpiration:       models.Expiration{Type: models.Duration, Duration: &caDurChild2},
					IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: &caIss},
					ParentID:           childCALvl1.ID,
					ID:                 "Lvl2",
				})
				if err != nil {
					t.Fatalf("failed creating the second CA child: %s", err)
				}

				fmt.Println("=============================")
				fmt.Println("CN:" + childCALvl2.Subject.CommonName)
				fmt.Println("ID:" + childCALvl2.ID)
				fmt.Println("SN:" + childCALvl2.SerialNumber)
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
			name: "ERR/ChildCAExpiresAfterRootCA",
			before: func(svc services.CAService) error {

				return nil
			},
			run: func(caSDK services.CAService) ([]models.CACertificate, error) {
				var cas []models.CACertificate
				caDurChild1 := models.TimeDuration(time.Hour * 26)
				caDurRootCA := models.TimeDuration(time.Hour * 25)

				caIss := models.TimeDuration(time.Minute * 3)

				rootCA, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:            models.Subject{CommonName: "CA Lvl 1"},
					CAExpiration:       models.Expiration{Type: models.Duration, Duration: &caDurRootCA},
					IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: &caIss},
				})

				if err != nil {
					t.Fatalf("failed creating the root CA: %s", err)
				}
				cas = append(cas, *rootCA)
				_, err = caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:            models.Subject{CommonName: "CA Lvl 1"},
					CAExpiration:       models.Expiration{Type: models.Duration, Duration: &caDurChild1},
					IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: &caIss},
					ParentID:           rootCA.ID,
					ID:                 "Lvl1",
				})

				//cas := []*models.CACertificate{}

				return cas, err
			},
			resultCheck: func(cas []models.CACertificate, err error) error {

				if err == nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}

				return nil
			},
		},
		{
			name: "OK/TesHightDateLimitRootCA",
			before: func(svc services.CAService) error {

				return nil
			},
			run: func(caSDK services.CAService) ([]models.CACertificate, error) {
				var cas []models.CACertificate
				caRDLim := time.Date(3000, 12, 1, 0, 0, 0, 0, time.Local)   // expires the 1st of december of 3000
				caCDLim1 := time.Date(3000, 11, 28, 0, 0, 0, 0, time.Local) // expires the 28th of november of 3000
				caCDLim2 := time.Date(3000, 11, 27, 0, 0, 0, 0, time.Local) // expires the 27 of november of 3000

				issuanceDur := time.Date(3000, 11, 20, 0, 0, 0, 0, time.Local) // fixed issuance: the 20 of november of 3000
				ca, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:            models.Subject{CommonName: DefaultCACN},
					CAExpiration:       models.Expiration{Type: models.Time, Time: &caRDLim},
					IssuanceExpiration: models.Expiration{Type: models.Time, Time: &issuanceDur},
				})
				if err != nil {
					t.Fatalf("failed creating the first CA child: %s", err)
				}
				cas = append(cas, *ca)

				fmt.Println("=============================")
				fmt.Println("CN:" + ca.Subject.CommonName)
				fmt.Println("ID:" + ca.ID)
				fmt.Println("SN:" + ca.SerialNumber)
				fmt.Println("=============================")

				caIss := time.Date(2030, 11, 20, 0, 0, 0, 0, time.Local)

				childCALvl1, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:            models.Subject{CommonName: "CA Lvl 1"},
					CAExpiration:       models.Expiration{Type: models.Time, Time: &caCDLim1},
					IssuanceExpiration: models.Expiration{Type: models.Time, Time: &caIss},
					ParentID:           ca.ID,
				})
				if err != nil {
					t.Fatalf("failed creating the first CA child: %s", err)
				}
				cas = append(cas, *childCALvl1)
				fmt.Println("=============================")
				fmt.Println("CN:" + childCALvl1.Subject.CommonName)
				fmt.Println("ID:" + childCALvl1.ID)
				fmt.Println("SN:" + childCALvl1.SerialNumber)
				fmt.Println("=============================")

				childCALvl2, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:            models.Subject{CommonName: "CA Lvl 1"},
					CAExpiration:       models.Expiration{Type: models.Time, Time: &caCDLim2},
					IssuanceExpiration: models.Expiration{Type: models.Time, Time: &caIss},
					ParentID:           childCALvl1.ID,
				})
				if err != nil {
					t.Fatalf("failed creating the first CA child: %s", err)
				}

				fmt.Println("=============================")
				fmt.Println("CN:" + childCALvl2.Subject.CommonName)
				fmt.Println("ID:" + childCALvl2.ID)
				fmt.Println("SN:" + childCALvl2.SerialNumber)
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
			name: "ERR/ChildCAExpiresAfterParentCA-UsingFixedDates",
			before: func(svc services.CAService) error {
				return nil
			},
			run: func(caSDK services.CAService) ([]models.CACertificate, error) {
				var cas []models.CACertificate
				caRDLim := time.Date(2030, 12, 1, 0, 0, 0, 0, time.Local)
				caCDLim1 := time.Date(2030, 12, 2, 0, 0, 0, 0, time.Local)

				caIss := time.Date(2030, 11, 20, 0, 0, 0, 0, time.Local)
				ca, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:            models.Subject{CommonName: DefaultCACN},
					CAExpiration:       models.Expiration{Type: models.Time, Time: &caRDLim},
					IssuanceExpiration: models.Expiration{Type: models.Time, Time: &caIss},
				})

				if err != nil {
					return nil, err
				}

				cas = append(cas, *ca)
				_, err = caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:            models.Subject{CommonName: "CA Lvl 1"},
					CAExpiration:       models.Expiration{Type: models.Time, Time: &caCDLim1},
					IssuanceExpiration: models.Expiration{Type: models.Time, Time: &caIss},
					ParentID:           ca.ID,
				})

				//cas := []*models.CACertificate{}

				return cas, err
			},
			resultCheck: func(cas []models.CACertificate, err error) error {

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
			run: func(caSDK services.CAService) ([]models.CACertificate, error) {
				var cas []models.CACertificate
				caRDLim := time.Date(3000, 12, 1, 0, 0, 0, 0, time.Local)
				caDurChild1 := models.TimeDuration(time.Hour * 26)

				caIss := time.Date(3000, 11, 20, 0, 0, 0, 0, time.Local)
				ca, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:            models.Subject{CommonName: DefaultCACN},
					CAExpiration:       models.Expiration{Type: models.Time, Time: &caRDLim},
					IssuanceExpiration: models.Expiration{Type: models.Time, Time: &caIss},
				})

				if err != nil {
					return nil, err
				}

				cas = append(cas, *ca)
				caIss2 := models.TimeDuration(time.Minute * 3)

				childCALvl1, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
					KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
					Subject:            models.Subject{CommonName: "CA Lvl 1"},
					CAExpiration:       models.Expiration{Type: models.Duration, Duration: &caDurChild1},
					IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: &caIss2},
					ParentID:           ca.ID,
				})
				cas = append(cas, *childCALvl1)

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

			err = caTest.BeforeEach()
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

type CATestServer struct {
	Service    services.CAService
	HttpCASDK  services.CAService
	BeforeEach func() error
	AfterSuite func()
}

func initCA(caSDK services.CAService) (*models.CACertificate, error) {
	caDUr := models.TimeDuration(time.Hour * 25)
	issuanceDur := models.TimeDuration(time.Minute * 12)
	ca, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
		ID:                 DefaultCAID,
		KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:            models.Subject{CommonName: DefaultCACN},
		CAExpiration:       models.Expiration{Type: models.Duration, Duration: &caDUr},
		IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: &issuanceDur},
	})

	return ca, err
}

func BuildCATestServer() (*CATestServer, error) {
	vaultSDKConf, vaultSuite := vault_test.BeforeSuite()

	pConfig, postgresSuite := postgres_test.BeforeSuite([]string{"ca", "devicemanager"})

	svc, port, err := AssembleCAServiceWithHTTPServer(config.CAConfig{
		BaseConfig: config.BaseConfig{
			Logs: config.BaseConfigLogging{
				Level: config.Info,
			},
			Server: config.HttpServer{
				LogLevel:           config.Info,
				HealthCheckLogging: false,
				Protocol:           config.HTTP,
			},
			EventBus: config.EventBusEngine{Enabled: false},
		},
		Storage: config.PluggableStorageEngine{
			LogLevel: config.Info,
			Provider: config.Postgres,
			Postgres: pConfig,
		},
		CryptoEngines: config.CryptoEngines{
			LogLevel:      config.Info,
			DefaultEngine: "filesystem-1",
			GolangProvider: []config.GolangEngineConfig{
				{
					ID:               "filesystem-1",
					Metadata:         map[string]interface{}{},
					StorageDirectory: "/tmp/lms-test/",
				},
			},
			HashicorpVaultKV2Provider: []config.HashicorpVaultCryptoEngineConfig{
				{
					ID:                "vault-1",
					HashicorpVaultSDK: vaultSDKConf,
					Metadata:          map[string]interface{}{},
				},
			},
		},
		CryptoMonitoring: config.CryptoMonitoring{
			Enabled: false,
		},
		VAServerDomain: "http://dev.lamassu.test",
	}, models.APIServiceInfo{
		Version:   "test",
		BuildSHA:  "-",
		BuildTime: "-",
	})
	fmt.Println(vaultSDKConf.Port)
	fmt.Println(vaultSuite.GetRootToken())

	if err != nil {
		return nil, fmt.Errorf("could not assemble CA with HTTP server")
	}

	return &CATestServer{
		Service:   *svc,
		HttpCASDK: clients.NewHttpCAClient(http.DefaultClient, fmt.Sprintf("http://127.0.0.1:%d", port)),
		BeforeEach: func() error {
			err := postgresSuite.BeforeEach()
			if err != nil {
				return fmt.Errorf("could not run postgres BeforeEach: %s", err)
			}

			//reinitialize tables schemas
			_, err = postgres.NewCAPostgresRepository(postgresSuite.DB["ca"])
			if err != nil {
				return fmt.Errorf("could not run reinitialize CA tables: %s", err)
			}

			_, err = postgres.NewCertificateRepository(postgresSuite.DB["ca"])
			if err != nil {
				return fmt.Errorf("could not run reinitialize Certificates tables: %s", err)
			}

			err = vaultSuite.BeforeEach()
			if err != nil {
				return fmt.Errorf("could not run vault BeforeEach: %s", err)
			}

			return nil
		},
		AfterSuite: func() {
			fmt.Println("TEST CLEANUP")
			postgresSuite.AfterSuite()
			vaultSuite.AfterSuite()
		},
	}, nil
}
