package routes

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lamassuiot/lamassuiot/pkg/v3/clients"
	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/cryptoengines"
	"github.com/lamassuiot/lamassuiot/pkg/v3/errs"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/resources"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
	"github.com/lamassuiot/lamassuiot/pkg/v3/storage/postgres"
	vault_test "github.com/lamassuiot/lamassuiot/pkg/v3/test/cryptoengines/keyvaultkv2"
	postgres_test "github.com/lamassuiot/lamassuiot/pkg/v3/test/storage/postgres"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
	"gorm.io/gorm"
)

const DefaultCAID = "111111-2222"
const DefaultCACN = "MyCA"

func TestCryptoEngines(t *testing.T) {

	caTest, err := BuildCATestServer()
	if err != nil {
		t.Fatalf("could not create CA test server")
	}
	caTest.HttpServer.Start()
	defer func() {
		caTest.AfterSuite()
	}()

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
			//
			// err := postgres_test.BeforeEach()
			// fmt.Errorf("Error while running BeforeEach job: %s", err)

			err = caTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' cleanup func in test case: %s", err)
			}

			caSDK := clients.NewHttpCAClient(http.DefaultClient, caTest.HttpServer.URL)
			err = tc.resultCheck(caSDK.GetCryptoEngineProvider(context.Background()))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}

		})
	}
}
func TestCreateCA(t *testing.T) {

	caTest, err := BuildCATestServer()
	if err != nil {
		t.Fatalf("could not create CA test server")
	}
	caTest.HttpServer.Start()
	defer func() {
		caTest.AfterSuite()
	}()

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
			//
			// err := postgres_test.BeforeEach()
			// fmt.Errorf("Error while running BeforeEach job: %s", err)

			err = caTest.BeforeEach()
			if err != nil {
				t.Fatalf("failed running 'BeforeEach' cleanup func in test case: %s", err)
			}

			caSDK := clients.NewHttpCAClient(http.DefaultClient, caTest.HttpServer.URL)
			err = tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(caSDK))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}

		})
	}
}
func TestGetCertificatesByCaAndStatus(t *testing.T) {

	caTest, err := BuildCATestServer()
	if err != nil {
		t.Fatalf("could not create CA test server")
	}
	caTest.HttpServer.Start()
	defer func() {
		caTest.AfterSuite()
	}()

	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) ([]*models.Certificate, error)
		resultCheck func(certs []*models.Certificate, err error) error
	}{
		{
			name: "OK/Pagination-with-100-certificates",
			before: func(svc services.CAService) error {
				certsToIssue := 100
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
					ListInput: services.ListInput[models.Certificate]{
						ExhaustiveRun: true,
						QueryParameters: &resources.QueryParameters{
							PageSize: 20,
						},
						ApplyFunc: func(elem *models.Certificate) {
							derefCert := *elem
							issuedCerts = append(issuedCerts, &derefCert)
						},
					},
				})

				return issuedCerts, err
			},
			resultCheck: func(certs []*models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error, but got error: %s", err)
				}

				if len(certs) != 100 {
					return fmt.Errorf("The function get certificate by ca and status does not return the correct count of the certificates %d", len(certs))
				} else {

				}
				return nil
			},
		},
		{
			name: "OK/PaginationWithoutExhaustuveRun",
			before: func(svc services.CAService) error {
				certsToIssue := 100
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
					ListInput: services.ListInput[models.Certificate]{
						ExhaustiveRun: false,
						QueryParameters: &resources.QueryParameters{
							PageSize: 20,
						},
						ApplyFunc: func(elem *models.Certificate) {
							derefCert := *elem
							issuedCerts = append(issuedCerts, &derefCert)
						},
					},
				})

				return issuedCerts, err
			},
			resultCheck: func(certs []*models.Certificate, err error) error {
				if err != nil {
					return fmt.Errorf("should've got no error, but got error: %s", err)
				}

				if len(certs) != 20 {
					return fmt.Errorf("The exhaustive run fuctionality of the function get certificate by ca and status is not working correctly  %d", len(certs))
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
				t.Fatalf("failed running 'BeforeEach' cleanup func in test case: %s", err)
			}

			_, err = initCA(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'initCA' func in test case: %s", err)
			}

			caSDK := clients.NewHttpCAClient(http.DefaultClient, caTest.HttpServer.URL)
			err = tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(caSDK))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}

		})
	}
}
func TestRevokeCA(t *testing.T) {

	caTest, err := BuildCATestServer()
	if err != nil {
		t.Fatalf("could not create CA test server")
	}
	caTest.HttpServer.Start()
	defer func() {
		caTest.AfterSuite()
	}()
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
						return fmt.Errorf("issued certificate should have Revoked status but is in %s status", revokedCA.Status)
					}
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

			caSDK := clients.NewHttpCAClient(http.DefaultClient, caTest.HttpServer.URL)

			_, err = initCA(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'init CA' func in test case: %s", err)
			}

			ca, err := tc.run(caSDK)
			if err != nil {
				t.Fatalf("failed running 'run' func in test case: %s", err)
			}

			issuedCerts := []*models.Certificate{}
			caTest.Service.GetCertificatesByCA(context.Background(), services.GetCertificatesByCAInput{
				CAID: DefaultCAID,
				ListInput: services.ListInput[models.Certificate]{
					QueryParameters: &resources.QueryParameters{},
					ExhaustiveRun:   true,
					ApplyFunc: func(elem *models.Certificate) {
						derefCert := *elem
						issuedCerts = append(issuedCerts, &derefCert)
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
func TestGetCAsByCommonName(t *testing.T) {

	caTest, err := BuildCATestServer()
	if err != nil {
		t.Fatalf("could not create CA test server")
	}
	caTest.HttpServer.Start()
	defer func() {
		caTest.AfterSuite()
	}()
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
					ApplyFunc: func(cert *models.CACertificate) {
						deref := *cert
						cas = append(cas, &deref)
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

			caSDK := clients.NewHttpCAClient(http.DefaultClient, caTest.HttpServer.URL)
			err = tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(caSDK))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}

		})
	}
}

func TestGetStats(t *testing.T) {
	caTest, err := BuildCATestServer()
	if err != nil {
		t.Fatalf("could not create CA test server")
	}
	caTest.HttpServer.Start()
	defer func() {
		caTest.AfterSuite()
	}()
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

			caSDK := clients.NewHttpCAClient(http.DefaultClient, caTest.HttpServer.URL)
			err = tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(caSDK))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func TestImportCA(t *testing.T) {

	caTest, err := BuildCATestServer()
	if err != nil {
		t.Fatalf("could not create CA test server")
	}
	caTest.HttpServer.Start()
	defer func() {
		caTest.AfterSuite()
	}()

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
					fmt.Errorf("Failed creating the certificate %s", err)
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
					fmt.Errorf("Failed importing the new CA to Lamassu %s", err)
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
					fmt.Errorf("Failed creating the certificate %s", err)
				}
				_, err = caSDK.ImportCA(context.Background(), services.ImportCAInput{
					ID:     "c1acdb823dd8ac113d2b0a1aaa03e6a4e0bf7d8adef322c06987baca",
					CAType: models.CertificateTypeImported,
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
					fmt.Errorf("Failed importing the new CA to Lamassu %s", err)
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
					fmt.Errorf("Failed creating the certificate %s", err)
				}
				engines, _ := caSDK.GetCryptoEngineProvider(context.Background())

				fmt.Println(engines)
				_, err = caSDK.ImportCA(context.Background(), services.ImportCAInput{
					ID:     "c1acdb823dd8ac113d2b0a1aaa03e6a4e0bf7d8adef322c06987baca",
					CAType: models.CertificateTypeImported,
					IssuanceExpiration: models.Expiration{
						Type:     models.Duration,
						Duration: (*models.TimeDuration)(&duration),
					},
					CACertificate: (*models.X509Certificate)(ca),
					CARSAKey:      (key).(*rsa.PrivateKey),
					KeyType:       models.KeyType(x509.RSA),
					EngineID:      engines[0].ID,

					//Here are missing a lot of parameterss
				})
				if err != nil {
					fmt.Errorf("Failed importing the new CA to Lamassu %s", err)
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
					fmt.Errorf("Failed creating the certificate %s", err)
				}
				_, err = caSDK.ImportCA(context.Background(), services.ImportCAInput{
					ID:     "c1acdb823dd8ac113d2b0a1aaa0adef322c06987baca",
					CAType: models.CertificateTypeImported,
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
					fmt.Errorf("Failed importing the new CA to Lamassu %s", err)
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
					fmt.Errorf("Failed creating the certificate %s", err)
				}
				_, err = caSDK.ImportCA(context.Background(), services.ImportCAInput{
					CAType: models.CertificateTypeImported,
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
					fmt.Errorf("Failed importing the new CA to Lamassu %s", err)
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

			caSDK := clients.NewHttpCAClient(http.DefaultClient, caTest.HttpServer.URL)
			err = tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(caSDK))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}

		})
	}
}

func TestDeleteCA(t *testing.T) {

	caTest, err := BuildCATestServer()
	if err != nil {
		t.Fatalf("could not create CA test server")
	}
	caTest.HttpServer.Start()
	defer func() {
		caTest.AfterSuite()
	}()
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

			caSDK := clients.NewHttpCAClient(http.DefaultClient, caTest.HttpServer.URL)
			err = tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(caSDK))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

/*
	func TestSignatureVerify(t *testing.T) {
		caTest, err := BuildCATestServer()
		if err != nil {
			t.Fatalf("could not create CA test server")
		}
		caTest.HttpServer.Start()
		defer func() {
			caTest.AfterSuite()
		}()
		var testcases = []struct {
			name        string
			before      func(svc services.CAService) error
			run         func(caSDK services.CAService) (*models.CAStats, error)
			resultCheck func(*models.CAStats, error) error
		}{
			{
				name:   "OK/TestSignatureVerify",
				before: func(svc services.CAService) error { return nil },
				run: func(caSDK services.CAService) (*models.CAStats, error) {

					//cas := []*models.CACertificate{}
					res, err := caSDK.SignatureVerify(context.Background(), services.SignatureVerifyInput{
						CAID: DefaultCAID,
						Signature: ,
						SigningAlgorithm: "RSASSA_PSS_SHA_512",
					})
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

				caSDK := clients.NewHttpCAClient(http.DefaultClient, caTest.HttpServer.URL)
				err = tc.before(caTest.Service)
				if err != nil {
					t.Fatalf("failed running 'before' func in test case: %s", err)
				}

				err = tc.resultCheck(tc.run(caSDK))
				if err != nil {
					t.Fatalf("unexpected result in test case: %s", err)
				}
			})
		}
	}
*/

func TestUpdateCAMetadata(t *testing.T) {
	caTest, err := BuildCATestServer()
	if err != nil {
		t.Fatalf("could not create CA test server")
	}
	caTest.HttpServer.Start()
	defer func() {
		caTest.AfterSuite()
	}()
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
					fmt.Println("ads")
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

			caSDK := clients.NewHttpCAClient(http.DefaultClient, caTest.HttpServer.URL)
			err = tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(caSDK))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

func TestCABySerialNumber(t *testing.T) {
	caTest, err := BuildCATestServer()
	if err != nil {
		t.Fatalf("could not create CA test server")
	}
	caTest.HttpServer.Start()
	defer func() {
		caTest.AfterSuite()
	}()
	var testcases = []struct {
		name        string
		before      func(svc services.CAService) error
		run         func(caSDK services.CAService) error
		resultCheck func(error) error
	}{
		{
			name: "OK/CASerialNumber",
			before: func(svc services.CAService) error {
				return nil
			},
			run: func(caSDK services.CAService) error {
				ca, err := caSDK.GetCAByID(context.Background(), services.GetCAByIDInput{
					CAID: DefaultCAID,
				})
				if err != nil {
					t.Fatalf("failed getting the ca by id: %s", err)
				}
				ca, err = caSDK.GetCABySerialNumber(context.Background(), services.GetCABySerialNumberInput{
					SerialNumber: ca.Certificate.SerialNumber,
				})
				if err != nil {
					t.Fatalf("failed getting the ca by serial number: %s", err)
				}
				fmt.Println(ca)
				return err
			},
			resultCheck: func(err error) error {
				if err != nil {
					return fmt.Errorf("should've not got error. But got error")
				}
				return nil
			},
		},
		{
			name: "Err/CACAIDIncorrect",
			before: func(svc services.CAService) error {
				return nil
			},
			run: func(caSDK services.CAService) error {
				//cas := []*models.CACertificate{}
				ca, err := caSDK.GetCAByID(context.Background(), services.GetCAByIDInput{
					CAID: "adsdwerffds",
				})
				if err != nil {
					return err
				}
				ca, err = caSDK.GetCABySerialNumber(context.Background(), services.GetCABySerialNumberInput{
					SerialNumber: ca.Certificate.SerialNumber,
				})
				if err != nil {
					t.Fatalf("failed getting the ca by serial number: %s", err)
				}
				fmt.Println(ca)
				return err
			},
			resultCheck: func(err error) error {
				if err == nil {
					return fmt.Errorf("should've got error. Got none")
				}
				return nil
			},
		},
		{
			name: "Err/CertificaterSerialNumberIncorrect",
			before: func(svc services.CAService) error {
				return nil
			},
			run: func(caSDK services.CAService) error {
				//cas := []*models.CACertificate{}
				ca, err := caSDK.GetCAByID(context.Background(), services.GetCAByIDInput{
					CAID: DefaultCAID,
				})
				if err != nil {
					t.Fatalf("failed getting the ca by id: %s", err)
				}
				ca, err = caSDK.GetCABySerialNumber(context.Background(), services.GetCABySerialNumberInput{
					SerialNumber: "asdadsd",
				})
				if err != nil {
					return err
				}
				fmt.Println(ca)
				return err
			},
			resultCheck: func(err error) error {
				if err == nil {
					return fmt.Errorf("should've got error. Got none")
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

			caSDK := clients.NewHttpCAClient(http.DefaultClient, caTest.HttpServer.URL)
			err = tc.before(caTest.Service)
			if err != nil {
				t.Fatalf("failed running 'before' func in test case: %s", err)
			}

			err = tc.resultCheck(tc.run(caSDK))
			if err != nil {
				t.Fatalf("unexpected result in test case: %s", err)
			}
		})
	}
}

type CATestServer struct {
	Service    services.CAService
	HttpServer *httptest.Server
	BeforeEach func() error
	AfterSuite func() error
}

func initCA(caSDK services.CAService) (*models.CACertificate, error) {
	caDUr := models.TimeDuration(time.Hour * 24)
	issuanceDur := models.TimeDuration(time.Hour * 12)
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
	lgr := logrus.StandardLogger().WithField("", "")
	vaultDocker := vault_test.NewVaultDockerTest()
	vaultEngine, err := cryptoengines.NewVaultKV2Engine(lgr, config.HashicorpVaultCryptoEngineConfig{
		HashicorpVaultSDK: vaultDocker.Config,
		ID:                "hCorp-vault",
		Metadata: map[string]interface{}{
			"deploy": "docker-test",
		},
	})
	if err != nil {
		return nil, fmt.Errorf("could not create Vault Crypto Engine")
	}

	postgresTest := postgres_test.NewPostgresDockerTest("ca_test")

	dbCli, err := postgres.CreatePostgresDBConnection(logrus.NewEntry(logrus.StandardLogger()), postgresTest.Config, "ca_test")
	if err != nil {
		return nil, fmt.Errorf("could not create CouchDB In-Memory DB: %s", err)
	}

	caStore, err := postgres.NewCAPostgresRepository(dbCli)
	if err != nil {
		return nil, fmt.Errorf("could not create CA store: %s", err)
	}

	certStore, err := postgres.NewCertificateRepository(dbCli)
	if err != nil {
		return nil, fmt.Errorf("could not create cert store: %s", err)
	}

	caSvc, err := services.NewCAService(services.CAServiceBuilder{
		Logger:             lgr,
		CAStorage:          caStore,
		CertificateStorage: certStore,
		CryptoMonitoringConf: config.CryptoMonitoring{
			Enabled: false,
		},
		CryptoEngines: map[string]*services.Engine{
			"filesystem-go": &services.Engine{
				Default: true,
				Service: cryptoengines.NewGolangPEMEngine(lgr, config.GolangEngineConfig{
					ID:               "filesystem-go",
					Metadata:         map[string]interface{}{},
					StorageDirectory: fmt.Sprintf("/tmp/%s", uuid.New()),
				}),
			},
			"hCorp-vault": &services.Engine{
				Service: vaultEngine,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("could not create CA Service: %s", err)
	}
	//AVeriguate it why the testig procedure is different
	router := NewCAHTTPLayer(lgr, caSvc)
	caServer := httptest.NewUnstartedServer(router)

	return &CATestServer{
		Service:    caSvc,
		HttpServer: caServer,
		BeforeEach: func() error {
			err := postgresTest.BeforeEach(func(db *gorm.DB) error {
				_, err := postgres.NewCAPostgresRepository(dbCli)
				if err != nil {
					return fmt.Errorf("could not create CA store: %s", err)
				}

				_, err = postgres.NewCertificateRepository(dbCli)
				if err != nil {
					return fmt.Errorf("could not create cert store: %s", err)
				}

				return nil
			})
			if err != nil {
				return fmt.Errorf("could not run postgres BeforeEach: %s", err)
			}

			err = vaultDocker.BeforeEach()
			if err != nil {
				return fmt.Errorf("could not run vault BeforeEach: %s", err)
			}

			return nil
		},
		AfterSuite: func() error {
			err := postgresTest.AfterSuite()
			if err != nil {
				return fmt.Errorf("could not run postgres AfterSuite: %s", err)
			}

			err = vaultDocker.AfterSuite()
			if err != nil {
				return fmt.Errorf("could not run vault AfterSuite: %s", err)
			}

			return nil
		},
	}, nil
}
