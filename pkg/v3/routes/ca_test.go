package routes

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lamassuiot/lamassuiot/pkg/v3/clients"
	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/cryptoengines"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
	"github.com/lamassuiot/lamassuiot/pkg/v3/storage/postgres"
	postgres_test "github.com/lamassuiot/lamassuiot/pkg/v3/storage/postgres/test"
	"github.com/sirupsen/logrus"
)

func TestCreateCA(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
	}{
		{
			name: "OK/CA",
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
			caDUr := models.TimeDuration(time.Hour * 24)
			issuanceDur := models.TimeDuration(time.Hour * 12)
			ca, err := caSDK.CreateCA(context.Background(), services.CreateCAInput{
				ID:                 "12345-11111",
				KeyMetadata:        models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
				Subject:            models.Subject{CommonName: "TestCA"},
				CAExpiration:       models.Expiration{Type: models.Duration, Duration: &caDUr},
				IssuanceExpiration: models.Expiration{Type: models.Duration, Duration: &issuanceDur},
			})
			if err != nil {
				t.Fatalf("could not create CA: %s", err)
			}

			fmt.Println(ca)

		})
		postgres_test.AfterSuite()
	}
}

type CATestServer struct {
	Service    services.CAService
	HttpServer *httptest.Server
}

func BuildCATestServer() (*CATestServer, error) {
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

	lgr := logrus.StandardLogger().WithField("", "")
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
