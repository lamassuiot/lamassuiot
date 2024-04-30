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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
	"golang.org/x/crypto/ocsp"
)

const DefaultCAID = "111111-2222"
const DefaultCACN = "MyCA"

func TestCryptoEngines(t *testing.T) {
	serverTest, err := StartCAServiceTestServer(t, false)
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
	serverTest, err := StartCAServiceTestServer(t, false)
	if err != nil {
		t.Fatalf("could not create CA test server: %s", err)
	}

	caTest := serverTest.CA

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

			err = serverTest.BeforeEach()
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
	serverTest, err := StartCAServiceTestServer(t, false)
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
func TestRevokeCA(t *testing.T) {
	serverTest, err := StartCAServiceTestServer(t, false)
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
	serverTest, err := StartCAServiceTestServer(t, false)
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
	serverTest, err := StartCAServiceTestServer(t, false)
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
	serverTest, err := StartCAServiceTestServer(t, false)
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
	serverTest, err := StartCAServiceTestServer(t, false)
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
	serverTest, err := StartCAServiceTestServer(t, false)
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
	serverTest, err := StartCAServiceTestServer(t, false)
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
				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}

				if len(certs) != 20 {
					return fmt.Errorf("should've got 20 certificates. Got %d", len(certs))
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

func TestGetCertificatesByCA(t *testing.T) {
	serverTest, err := StartCAServiceTestServer(t, false)
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
				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}

				if len(certs) != 20 {
					return fmt.Errorf("should've got 20 certificates. Got %d", len(certs))
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
					CAID: "MyCA",
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
					CAID: "MyCA",
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
	serverTest, err := StartCAServiceTestServer(t, false)
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
		run         func(caSDK services.CAService) (*models.CACertificate, error)
		resultCheck func(*models.CACertificate, error) error
	}{
		{
			name:   "OK/ImportingExternalCA",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.CACertificate, error) {
				ca, _, err := generateSelfSignedCA(x509.RSA)
				var duration time.Duration = 100
				if err != nil {
					return nil, fmt.Errorf("Failed creating the certificate %s", err)
				}

				importedCA, err := caSDK.ImportCA(context.Background(), services.ImportCAInput{
					ID:     "c1acdb823dd8ac113d2b0a1aaa03e6abf45b4d24e0bf7d8adef322c06987baca",
					CAType: models.CertificateTypeExternal,
					IssuanceExpiration: models.Expiration{
						Type:     models.Duration,
						Duration: (*models.TimeDuration)(&duration),
					},
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
			name:   "OK/ImportingExternalCA",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.CACertificate, error) {
				ca, key, err := generateSelfSignedCA(x509.RSA)
				var duration time.Duration = 100
				if err != nil {
					return nil, fmt.Errorf("Failed creating the certificate %s", err)
				}

				importedCA, err := caSDK.ImportCA(context.Background(), services.ImportCAInput{
					ID:     "c1acdb823dd8ac113d2b0a1aaa03e6a4e0bf7d8adef322c06987baca",
					CAType: models.CertificateTypeImportedWithKey,
					IssuanceExpiration: models.Expiration{
						Type:     models.Duration,
						Duration: (*models.TimeDuration)(&duration),
					},
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

				importedCA, err := caSDK.ImportCA(context.Background(), services.ImportCAInput{
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

				importedCA, err := caSDK.ImportCA(context.Background(), services.ImportCAInput{
					ID:     "c1acdb823dd8ac113d2b0a1aaa0adef322c06987baca",
					CAType: models.CertificateTypeImportedWithKey,
					IssuanceExpiration: models.Expiration{
						Type:     models.Duration,
						Duration: (*models.TimeDuration)(&duration),
					},
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

				importedCA, err := caSDK.ImportCA(context.Background(), services.ImportCAInput{
					CAType: models.CertificateTypeImportedWithKey,
					IssuanceExpiration: models.Expiration{
						Type:     models.Duration,
						Duration: (*models.TimeDuration)(&duration),
					},
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
			name:   "OK/ImportingHierarchy",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (*models.CACertificate, error) {
				ca0Crt := `-----BEGIN CERTIFICATE-----
MIIGUTCCBDmgAwIBAgIUYuInJ29SHCU4j8ixsu5saKNItKQwDQYJKoZIhvcNAQEL
BQAwSTEJMAcGA1UEBhMAMQkwBwYDVQQIEwAxCTAHBgNVBAcTADEJMAcGA1UEChMA
MQkwBwYDVQQLEwAxEDAOBgNVBAMTB1Jvb3QtQ0EwHhcNMjQwMjA4MTI1NTQ4WhcN
MjQxMjA0MTI1NTQ2WjBJMQkwBwYDVQQGEwAxCTAHBgNVBAgTADEJMAcGA1UEBxMA
MQkwBwYDVQQKEwAxCTAHBgNVBAsTADEQMA4GA1UEAxMHUm9vdC1DQTCCAiIwDQYJ
KoZIhvcNAQEBBQADggIPADCCAgoCggIBAKJ+YWC47TrR7nFzd36G22pqbe0k0Dbs
iA5bgKfZIilDwp5auIIUZQPfRSG8OFXB/BvEHP/iw99PfaE1i3i9TP03adwkweZE
fPdIwFaC4eu6dSdF/c9dqeRdeHn5lXGTaQCWywaf8BMLkcZgnOrSRt7HrDkEJUc8
s2aHsyEv0FD6mg55nZJxKWt3+J4OKHLxrP4VWXaTezspPq4XKl5XHGgDuH+Jej6u
qcyXmkhyH87VFideSeGWEOkAkGaWr93qSgTh/nWegaHW8dv+FQsQ0dFavUmUyjHF
slkGDX5URXWRjXogrCHh0u8SQDgN50V0CzJgK8J7L/l7eOjeeOM5plVQdaqLqGbc
a+q8j+yhWkPBnQJjmQ9rM7Y7IlEQdBFyTw9MwFZ+PyDM9x5NS8B1xJ0/wpOfxOo2
LAnP+YgsggETde44volHCfEDEJOf/xVr1S5O1hWLKC/kDGtZD1bD29AxTNph4tBI
hqHMfDjmJULoXyhLkQDU5KAF/OxicM7yFTecxXcXa4isbmcQHB1CTm5+kLtwiNDZ
enYww4KaOX8kGFTJGNWXlFVRifP2DmuDGBlUaGYZRhQlLrATnSLk4nLGY3GOLunC
8UBny93LYdyRQ41Fux0t2n4H6mrMaGIT9YN6X7qUeD/zPN+9tSMgNB9tD53Z2Y0L
szEnbIx7PzTnAgMBAAGjggEvMIIBKzAOBgNVHQ8BAf8EBAMCAZYwHQYDVR0lBBYw
FAYIKwYBBQUHAwIGCCsGAQUFBwMBMA8GA1UdEwEB/wQFMAMBAf8wLQYDVR0OBCYE
JDY3NTMyYTYxLTYxZGEtNDI0ZS05NmEyLTZjNjA2OWY2OTMyYjAvBgNVHSMEKDAm
gCQ2NzUzMmE2MS02MWRhLTQyNGUtOTZhMi02YzYwNjlmNjkzMmIwNwYIKwYBBQUH
AQEEKzApMCcGCCsGAQUFBzABhhtodHRwczovL2xhYi5sYW1hc3N1LmlvL29jc3Aw
UAYDVR0fBEkwRzBFoEOgQYY/aHR0cHM6Ly9sYWIubGFtYXNzdS5pby9jcmwvNjc1
MzJhNjEtNjFkYS00MjRlLTk2YTItNmM2MDY5ZjY5MzJiMA0GCSqGSIb3DQEBCwUA
A4ICAQCAyMmHG/bFKXdIWDDcOOQoG+BPLbfFpK17MZonW3r0pYf/LuqYZ9xOpsBG
LKohw046hcPPzApjJDoI0MtsUWhWaOTvxr1JWraVm25E1MTIBPPFnrCQypBnlHHk
TUihG3Wba1v2bXiWfuW0+pCFZsDNU8CLGvwSRwpZzVo61cnQjjC4mgit3RSoW8qb
6ZcI/YaGlb30GR/waJEADk47l2zDHL7kj4M5m96svPAwyM63QqxdeECPi5uqXwyt
c9r2SEpG4fOQ1UAO19MlbayvcrQwBTS7/lr5PUGBvhka9UTlsWhdn8DZAZV/ZPrw
Gl0/EuQdj58SPODW6RHemRUWHEciPtOHD+TgXT02XqYVg6jf9gSaodJHL9zis2jw
5myRi7nqXQdpM+DPvLcbSHTJW6ApzsuFe10RWus54OSNj2LlQ4B47n+D54kBRoe6
ABoAryHvsqA9f9IJddKVfjGkP7fs4E2slMyiQ4sNcsNwnduWuQ71qfi2mjAXqu3r
cQ0rJT0ev0kcp3pAre1jE1NhbGhNxzlhircijGAlSkqzaGzHlpbg8Sj7oB01n8qm
DA9exhv4hh1mr3bFuezyCE+RFXE1+WCypxn26YEzOrhkQo9yTY7p8ZZIq7Dr/PRI
EhOWz98nmVSio2NlV4ejsGi3YCS3lLlOKH2qEmj1qkkcPL03rA==
-----END CERTIFICATE-----
`

				ca0Key := `-----BEGIN RSA PRIVATE KEY-----
MIIJKgIBAAKCAgEAon5hYLjtOtHucXN3fobbampt7STQNuyIDluAp9kiKUPCnlq4
ghRlA99FIbw4VcH8G8Qc/+LD3099oTWLeL1M/Tdp3CTB5kR890jAVoLh67p1J0X9
z12p5F14efmVcZNpAJbLBp/wEwuRxmCc6tJG3sesOQQlRzyzZoezIS/QUPqaDnmd
knEpa3f4ng4ocvGs/hVZdpN7Oyk+rhcqXlccaAO4f4l6Pq6pzJeaSHIfztUWJ15J
4ZYQ6QCQZpav3epKBOH+dZ6Bodbx2/4VCxDR0Vq9SZTKMcWyWQYNflRFdZGNeiCs
IeHS7xJAOA3nRXQLMmArwnsv+Xt46N544zmmVVB1qouoZtxr6ryP7KFaQ8GdAmOZ
D2sztjsiURB0EXJPD0zAVn4/IMz3Hk1LwHXEnT/Ck5/E6jYsCc/5iCyCARN17ji+
iUcJ8QMQk5//FWvVLk7WFYsoL+QMa1kPVsPb0DFM2mHi0EiGocx8OOYlQuhfKEuR
ANTkoAX87GJwzvIVN5zFdxdriKxuZxAcHUJObn6Qu3CI0Nl6djDDgpo5fyQYVMkY
1ZeUVVGJ8/YOa4MYGVRoZhlGFCUusBOdIuTicsZjcY4u6cLxQGfL3cth3JFDjUW7
HS3afgfqasxoYhP1g3pfupR4P/M83721IyA0H20PndnZjQuzMSdsjHs/NOcCAwEA
AQKCAgBOFPSuCa7VSPOPSLDu99aPuDzCa6IyAk8OtyGHhmtH8OugNG/c8ffoeG07
3LolW2XN4dsditYchJIV2SkAB9brBqmzw2X5RIfYO/lQmOv+3kZVbOidsKBmwBOY
aTpKrU8TnWJJ+KjgPfr6nIpKvGiZvNEhRMC1DpIWfraxB8zOXN2SfxYcvIvuvGOX
b644LbG3FoM623un3hXkifUuCCX6RW9uuZ0oab3mNiNJFK38MaDHoiNWZ0oQ7Nh2
s4om1OJknkQsONKJ9kOaNundu2NXeobiyMCwUhN1e9cYEV6fNCYLvY95aI53mwmI
5gVv9mc6+cONXKyc8ZwUKnNknNsz97OeGdxpLFp1mquAS6zgLtkwsaZipX2yDeFr
a/OTCwuIGftm/Rkw3c8mklBwMIt3Yqo/eVt7zpQVzHDHVGl1m1xcvMsheSyAorXc
XbMHsfQsRolYGXae1hTUXhKDth/EVrMV4w1kQt9unFY2EIGa6vWBj8GjH5JqJ77g
7VDvlcjbq0P3F81h9ctXV6mMKL34f8xqJiYbN8fENGBL2QKej9snE/6QfJ0bV3qJ
/LneVB7DefdW1vpF6kidh0SGfu6NFEOJg0eRUOSube9vXznV0oIcOiaFZNA09Xt+
+1FsePphOqUA/m+6o8Yfu0g9YtX939M4HyDR7P9xeAC1gtD44QKCAQEAxn/UWYs0
m5SOZpG9EKTe2UhT36UNMyZz8SUMecxb2dvN9QF38J6Zt4HdiBQG/Vh+houlAXaN
+MNqgahs+vqTnzu66tlom8ndbzKKFUwD1RM2V1vhZlVPa6opK9G7sW9G59NfakIG
Pb7xo/j1tugIdK6ykLGE28Mjd9dUBX29TzZAMpUeOqDl+tnK01hC3ldQeGCLDl4V
VrbXc876TUhENn9IVV1cXXBJU9S01u0he3rhmUP7u/TfnGXfjbkCOT5gkwlCzNsV
+hhWTpAXx+ep8fnCeZaHfRpXS8pJgAtAZLQgystvR5PSL3pJoDvtFpgCLB5feW96
o2vwYfFkxG2CfQKCAQEA0ZB4FPWIziCJ6hhep8kZooHiB9BWA6IGM9menVySljfa
54lGV0Iupdy/u/VnU5WUJ5gCEPd3swVIQXwHi0Rtgys1qycNUb/qWn0MiW+vDoxl
dY/e3RImom4TEdatcDzIUNxCgHZLz+VMXjC3gWC1SyNeLZBp+1ym6ANh9j+KJtFt
i42uk7lKQZ3eQNrX7uPCkwIpqg7jMp623Sy39WvR2SGXwiXlJ7Dwm48PhhwoyDLc
SiAmOWkIRnadeTnCzPYkUl4imo8yb3oBU41pOSbZp7Xi48rX/xGwASdYSvZZftDL
5mIoOE29bvOf9MNwq/feg+JiWlvSPPSkTtgjnvbuMwKCAQEAo/6+cRBqcVNl5uXn
XxXnq3pvGSmi4yyUw5lJWmN1S2OnIBGLhzdxZkQbw65QLAVt2zkKJVBOcUT5/I8r
IpvdVMQjZJ4kJ/m6QYFuxbOcwvBxh/E4IrS+vgPCqhpISIrX+PYQMZjE0UStHTy1
vNytB8HBc3vGeU4aQoubNkIxIn1+wouiguultf8z7DJSZKGcsSeKG1+tn4vGKz7I
WwsmmCPGnghZJDV9z42/roYRkJPwSRD6rMnd6Lfd35gHd0XKwg/3qYoj+REcVSIF
E7qZFHq1qoCsBba6grpoySoClHChWwqCMI+3KlSM+Z4o/e6udMbPOGPa3aNy4Whv
ST30fQKCAQEAjTbu1CDIeS4QAUE+t42Zypn/OAi5jWUnDNV+Psfct4EX76HfVnlw
ebARO5UYdYh791pFOi2n6WiL0iTD6KLJsPPzDEwae5X5U9SkGBC8Q+9zhw7VvN64
TggirYieAt3Sljp2TZ5pY8Q9+9KUNYh3YhSJJ+cCo7FBf2KYJpmWfKXvTXTBySW4
1hKNa+KMU5wCx5FThhbWHow46T1zENwA4nHyk495pY9j808pxNNA3/b13rVfTJxs
SR8w6jlz/S14OFDavI/2CoyKTEUkPLDjRlIYfCt59ZVzprNemdT7ZatJWwuV0qsA
Fb3xcbwpNpimxvRMFlt9hjnMZpzbFAmNZQKCAQEAjHynUpHEJ74RtBTaunTzR43T
AE4xcmJs/JO16a3Mz6LTVnqKnE63TjVwdLLAiOQwaF8PlwGu60QN2VcpyY7nIZ4p
tUVlkv6quFhto4KXkhZCmH5xZCRR5omP6uNQMgnWsBKLOVav1EKBfLnYbHJVvqgk
MX2SR1CtsZ94hOmAsAUpbGayI0WPrelv8tk7j9XiZxtWXILFhs9SiDanXUE3d1L5
KS8m17E9pzUxT9d3G9phCrQ5MYlUkk/fYdw21/frX5A3gUxUxUUpVy61yUFybGZ4
m5TcjyTdwM+bqdPgt9QcTUluqcafW5CXRpPc450WQ8ZLpG3r7qqiHWx0NhNArw==
-----END RSA PRIVATE KEY-----
`

				ca1Crt := `-----BEGIN CERTIFICATE-----
MIIEfDCCAmSgAwIBAgIUY4nT09QvKBeOMmcYQtELjjkqiM8wDQYJKoZIhvcNAQEL
BQAwSTEJMAcGA1UEBhMAMQkwBwYDVQQIEwAxCTAHBgNVBAcTADEJMAcGA1UEChMA
MQkwBwYDVQQLEwAxEDAOBgNVBAMTB1Jvb3QtQ0EwHhcNMjQwMjA4MTMwMjI5WhcN
MjQwODI2MTMwMjI5WjBKMQkwBwYDVQQGEwAxCTAHBgNVBAgTADEJMAcGA1UEBxMA
MQkwBwYDVQQKEwAxCTAHBgNVBAsTADERMA8GA1UEAxMIQ0EtTHZMLTEwTjAQBgcq
hkjOPQIBBgUrgQQAIQM6AASzeuvq07rwTXZ54wGeFB+9ptfEIIm0bYp7KTAJgxz9
YBxYd7foEudkB5NCaYSmbdcPzjFyYX/L4aOCAS8wggErMA4GA1UdDwEB/wQEAwIB
ljAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUwAwEB
/zAtBgNVHQ4EJgQkY2IzMjllOTQtMDg5Zi00OGJkLThjYmYtZTBkOGMzMmE2MmYw
MC8GA1UdIwQoMCaAJDY3NTMyYTYxLTYxZGEtNDI0ZS05NmEyLTZjNjA2OWY2OTMy
YjA3BggrBgEFBQcBAQQrMCkwJwYIKwYBBQUHMAGGG2h0dHBzOi8vbGFiLmxhbWFz
c3UuaW8vb2NzcDBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwczovL2xhYi5sYW1hc3N1
LmlvL2NybC9jYjMyOWU5NC0wODlmLTQ4YmQtOGNiZi1lMGQ4YzMyYTYyZjAwDQYJ
KoZIhvcNAQELBQADggIBACVOvyRAvDSes/G9UB+QyIikn0Se70S6iz07m87QyGQb
N2zU3dy2K3ph01VB4plombYSB21LnlYqYp0mesSYyiIi9BhZDfbuBkLC/Ba8Mc+t
oOCONJ1KWi4HNJbB2FZLwg8vonDIzdSxgESFdjn1AuH68ZR0SFuy8IL9RGoUzM2I
hzg//VPMSz7sCccFn0MOGkSDlqxVNxqxO23OIaTUeBc0cJLitWy5H4F9Hhl0DQE4
Tf1HsXD91dWhnd7bta2S6o7vhmoIba1Y/tgct7VTUeC4EtvECJN94lS4L+6gDT8S
PVQBKti2p2AGBCJS5TocQaxixXAcKJTIiFPD/xH64RdR1K9iNpAsPXzMpbxTixNw
MRZnBxEEwxPXGGExq9+OKxrJIrSLH3eJkX1DiwmQY9d9o7oVVYOxaU2LdUaX+ZAy
qWn/efS+RB2SqVYCVqimd8mbUKm7zeA3PAcdlLzj6uwrqsuTPyT4EshjWZXVNOoL
w2sgbWAunX64yVyCsaXVf9VXgI7hBr4iCeOvnBnDCa7hk2CcVqhqJMOe3Br43H19
/KEpwDUNB3J7NKjFn4a2hNM5yExQYE6kp6QB9zIvVIbJQ4/piXnQGRNM5B9xgi9h
CaOhtzDKS768LjmoLtPVwiMk/9Aa3Iumlg7m89lJM35+rHnXbuMVZZ60TLcFMwEy
-----END CERTIFICATE-----
`
				ca1Key := `-----BEGIN EC PRIVATE KEY-----
MGgCAQEEHNF0jwKnZxd4sykSEaBL8QRMKqeL/GamSiWRCuWgBwYFK4EEACGhPAM6
AASzeuvq07rwTXZ54wGeFB+9ptfEIIm0bYp7KTAJgxz9YBxYd7foEudkB5NCaYSm
bdcPzjFyYX/L4Q==
-----END EC PRIVATE KEY-----`

				key0, err := helpers.ParsePrivateKey([]byte(strings.TrimSpace(ca0Key)))
				if err != nil {
					t.Fatalf("could not parse root private key: %s", err)
				}

				key1, err := helpers.ParsePrivateKey([]byte(strings.Trim(ca1Key, "	")))
				if err != nil {
					t.Fatalf("could not parse ca-lvl-1 private key: %s", err)
				}

				cert0, err := helpers.ParseCertificate(strings.Trim(ca0Crt, "	"))
				if err != nil {
					t.Fatalf("could not parse root cert: %s", err)
				}

				cert1, err := helpers.ParseCertificate(strings.Trim(ca1Crt, "	"))
				if err != nil {
					t.Fatalf("could not parse ca-lvl-1 cert: %s", err)
				}

				helpers.ParsePrivateKey([]byte(ca1Key))
				helpers.ParsePrivateKey([]byte(ca1Key))

				duration, _ := models.ParseDuration("100d")
				importedRootCA, err := caSDK.ImportCA(context.Background(), services.ImportCAInput{
					CAType: models.CertificateTypeImportedWithKey,
					IssuanceExpiration: models.Expiration{
						Type:     models.Duration,
						Duration: (*models.TimeDuration)(&duration),
					},
					CACertificate: (*models.X509Certificate)(cert0),
					CARSAKey:      (key0).(*rsa.PrivateKey),
					KeyType:       models.KeyType(x509.RSA),
				})
				if err != nil {
					t.Fatalf("could not import root CA: %s", err)
				}

				importedCALvl1, err := caSDK.ImportCA(context.Background(), services.ImportCAInput{
					CAType: models.CertificateTypeImportedWithKey,
					IssuanceExpiration: models.Expiration{
						Type:     models.Duration,
						Duration: (*models.TimeDuration)(&duration),
					},
					CACertificate: (*models.X509Certificate)(cert1),
					CAECKey:       (key1).(*ecdsa.PrivateKey),
					KeyType:       models.KeyType(x509.ECDSA),
					ParentID:      importedRootCA.ID,
				})

				return importedCALvl1, err

			},
			resultCheck: func(ca *models.CACertificate, err error) error {
				if err != nil {
					return fmt.Errorf("got unexpected error: %s", err)
				}

				if ca.Level != 1 {
					return fmt.Errorf("CA should be at level 1. Got %d", ca.Level)
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

	serverTest, err := StartCAServiceTestServer(t, false)
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

	serverTest, err := StartCAServiceTestServer(t, false)
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

func TestGetCertificatesByExpirationDate(t *testing.T) {

	serverTest, err := StartCAServiceTestServer(t, false)
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
					return fmt.Errorf("got unexpected error: %s", err)
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
					return fmt.Errorf("got unexpected error: %s", err)
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
					return fmt.Errorf("got unexpected error: %s", err)
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
	t.Skip("Skip until we have a reliable test for this")
	serverTest, err := StartCAServiceTestServer(t, false)
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
			name:   "OK/TestSignatureVerifyPlainMes",
			before: func(svc services.CAService) error { return nil },
			run: func(caSDK services.CAService) (bool, error) {

				messB := []byte("my Message")
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

				messB := []byte("my Message")
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
	serverTest, err := StartCAServiceTestServer(t, false)
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
	serverTest, err := StartCAServiceTestServer(t, false)
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
	serverTest, err := StartCAServiceTestServer(t, false)
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

			ca, err := serverTest.CA.Service.CreateCA(context.Background(), services.CreateCAInput{
				KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256},
				Subject:            models.Subject{CommonName: "MyCA"},
				CAExpiration:       models.Expiration{Type: models.Duration, Duration: &caDur},
				IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: &issuanceDur},
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
	ca, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
		ID:                 DefaultCAID,
		KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:            models.Subject{CommonName: DefaultCACN},
		CAExpiration:       models.Expiration{Type: models.Duration, Duration: &caDUr},
		IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: &issuanceDur},
	})

	return ca, err
}

func StartCAServiceTestServer(t *testing.T, withEventBus bool) (*TestServer, error) {
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

	storageConfig, err := PreparePostgresForTest([]string{"ca"})
	if err != nil {
		t.Fatalf("could not prepare Postgres test server: %s", err)
	}

	cryptoConfig := PrepareCryptoEnginesForTest([]CryptoEngine{GOLANG, VAULT})
	testServer, err := AssembleServices(storageConfig, eventBusConf, cryptoConfig, []Service{CA})
	if err != nil {
		t.Fatalf("could not assemble Server with HTTP server")
	}

	t.Cleanup(testServer.AfterSuite)

	return testServer, nil
}
