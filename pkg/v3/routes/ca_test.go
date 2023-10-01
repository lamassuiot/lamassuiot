package routes

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lamassuiot/lamassuiot/pkg/v3/clients"
	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/cryptoengines"
	"github.com/lamassuiot/lamassuiot/pkg/v3/errs"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
	"github.com/lamassuiot/lamassuiot/pkg/v3/storage/postgres"
	vault_test "github.com/lamassuiot/lamassuiot/pkg/v3/test/cryptoengines/keyvaultkv2"
	postgres_test "github.com/lamassuiot/lamassuiot/pkg/v3/test/storage/postgres"
	"github.com/sirupsen/logrus"
)

func TestCreateCA(t *testing.T) {
	t.Parallel()

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
			// t.Parallel()
			// err := postgres_test.BeforeEach()
			// fmt.Errorf("Error while running BeforeEach job: %s", err)

			caTest, err := BuildCATestServer()
			if err != nil {
				t.Fatalf("could not create CA test server")
			}
			caTest.HttpServer.Start()

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
		postgres_test.AfterSuite()
	}
}

type CATestServer struct {
	Service    services.CAService
	HttpServer *httptest.Server
}

func BuildCATestServer() (*CATestServer, error) {
	lgr := logrus.StandardLogger().WithField("", "")
	vaultCfg := vault_test.BeforeSuite()
	vaultEngine, err := cryptoengines.NewVaultKV2Engine(lgr, config.HashicorpVaultCryptoEngineConfig{
		HashicorpVaultSDK: vaultCfg,
		ID:                "hCorp-vault",
		Metadata: map[string]interface{}{
			"deploy": "docker-test",
		},
	})
	if err != nil {
		return nil, fmt.Errorf("could not create Vault Crypto Engine")
	}

	pConfig := postgres_test.BeforeSuite("ca_test")

	dbCli, err := postgres.CreatePostgresDBConnection(logrus.NewEntry(logrus.StandardLogger()), pConfig, "ca_test")
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

	router := NewCAHTTPLayer(lgr, caSvc)
	caServer := httptest.NewUnstartedServer(router)

	return &CATestServer{
		Service:    caSvc,
		HttpServer: caServer,
	}, nil
}
