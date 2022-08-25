package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/lamassuiot/lamassuiot/pkg/ca/common/api"
	postgresRepository "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/repository/postgres"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service"
	cryptoEngines "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service/crypto-engines"
	lamassuCATransport "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/transport"
	clientUtils "github.com/lamassuiot/lamassuiot/pkg/utils/client"
	"github.com/opentracing/opentracing-go"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"
)

//TODO: Complete testing of the client

func TestClientCreateCA(t *testing.T) {
	tt := []struct {
		name                  string
		serviceInitialization func(svc *service.Service)
		testRestEndpoint      func(c *LamassuCAClient)
	}{
		{
			name:                  "CreateCA",
			serviceInitialization: func(svc *service.Service) {},
			testRestEndpoint: func(c *LamassuCAClient) {
				_, err := (*c).CreateCA(context.Background(), &api.CreateCAInput{
					CAType: api.CATypePKI,
					Subject: api.Subject{
						CommonName:       "test",
						OrganizationUnit: "IoT",
						Organization:     "Lamassu",
						Country:          "ES",
						State:            "Gipuzkoa",
						Locality:         "Donostia",
					},
					KeyMetadata: api.KeyMetadata{
						KeyType: api.RSA,
						KeyBits: 2048,
					},
					CADuration:       time.Duration(24 * time.Hour),
					IssuanceDuration: time.Duration(12 * time.Hour),
				})

				if err != nil {
					t.Errorf("error was not expected while creating CA: %s", err)
				}
			},
		},
		{
			name:                  "DuplicateCreateCA",
			serviceInitialization: func(svc *service.Service) {},
			testRestEndpoint: func(c *LamassuCAClient) {
				_, err := (*c).CreateCA(context.Background(), &api.CreateCAInput{
					CAType: api.CATypePKI,
					Subject: api.Subject{
						CommonName:       "test",
						OrganizationUnit: "IoT",
						Organization:     "Lamassu",
						Country:          "ES",
						State:            "Gipuzkoa",
						Locality:         "Donostia",
					},
					KeyMetadata: api.KeyMetadata{
						KeyType: api.RSA,
						KeyBits: 2048,
					},
					CADuration:       time.Duration(24 * time.Hour),
					IssuanceDuration: time.Duration(12 * time.Hour),
				})

				if err != nil {
					t.Errorf("error was not expected while creating CA: %s", err)
				}

				_, err = (*c).CreateCA(context.Background(), &api.CreateCAInput{
					CAType: api.CATypePKI,
					Subject: api.Subject{
						CommonName:       "test",
						OrganizationUnit: "IoT",
						Organization:     "Lamassu",
						Country:          "ES",
						State:            "Gipuzkoa",
						Locality:         "Donostia",
					},
					KeyMetadata: api.KeyMetadata{
						KeyType: api.RSA,
						KeyBits: 2048,
					},
					CADuration:       time.Duration(24 * time.Hour),
					IssuanceDuration: time.Duration(12 * time.Hour),
				})

				if err == nil {
					t.Errorf("error was expected while creating duplicate CA")
				}

				if err.Error() != ErrDuplicateCA {
					t.Errorf("duplicate CA error was expected but got: %s", err)
				}
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			handler, svc := setup(t)
			mux := http.NewServeMux()

			mux.Handle("/v1/", http.StripPrefix("/v1", handler))

			server := httptest.NewServer(mux)
			defer server.Close()

			tc.serviceInitialization(&svc)
			serverUrl, err := url.Parse(server.URL)
			if err != nil {
				t.Fatalf("an error '%s' was not expected when parsing url", err)
			}

			c, err := NewLamassuCAClient(clientUtils.BaseClientConfigurationuration{
				URL:           serverUrl,
				AuthMethod:    clientUtils.AuthMethodNone,
				CACertificate: "",
			})
			if err != nil {
				t.Fatalf("an error '%s' was not expected when creating client", err)
			}
			tc.testRestEndpoint(&c)
		})
	}
}

func setup(t *testing.T) (http.Handler, service.Service) {
	var logger log.Logger

	logger = log.NewNopLogger()
	logger = level.NewFilter(logger, level.AllowDebug())
	logger = log.With(logger, "ts", log.DefaultTimestampUTC)
	logger = log.With(logger, "caller", log.DefaultCaller)

	dialector := sqlite.Open("")
	db, err := gorm.Open(dialector, &gorm.Config{
		Logger: gormLogger.Default.LogMode(gormLogger.Silent),
	})
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a gorm database connection", err)
	}

	certificateRepository := postgresRepository.NewPostgresDB(db, logger)
	tracer := opentracing.NoopTracer{}

	engine, _ := cryptoEngines.NewGolangPEMEngine(logger, "/home/ubuntu/lamassuiot/lamassuiot/pkg/tmp/tests")
	var s service.Service
	s = service.NewCAService(logger, engine, certificateRepository, "http://ocsp.test")
	s = service.LoggingMiddleware(logger)(s)

	handler := lamassuCATransport.MakeHTTPHandler(s, logger, tracer)
	return handler, s
}
