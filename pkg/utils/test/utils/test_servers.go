package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	clientUtils "github.com/lamassuiot/lamassuiot/pkg/utils/client"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server"
	"github.com/opentracing/opentracing-go"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"

	caClient "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	caRepository "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/repository/postgres"
	caService "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service"
	cryptoEngines "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service/crypto-engines"
	caTransport "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/transport"

	dmsClient "github.com/lamassuiot/lamassuiot/pkg/dms-manager/client"
	dmsRepository "github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/repository/postgres"
	dmsService "github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/service"
	dmsTransport "github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/transport"

	deviceStatsRepository "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/repository/badger"
	postgresRepository "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/repository/postgres"
	deviceService "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/service"
	deviceTransport "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/transport"

	estTransport "github.com/lamassuiot/lamassuiot/pkg/est/server/api/transport"

	ocspService "github.com/lamassuiot/lamassuiot/pkg/ocsp/server/api/service"
	ocspTransport "github.com/lamassuiot/lamassuiot/pkg/ocsp/server/api/transport"

	"github.com/lamassuiot/lamassuiot/pkg/alerts/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/alerts/server/api/service/outputchannels"
	alertsTransport "github.com/lamassuiot/lamassuiot/pkg/alerts/server/api/transport"
	"github.com/lamassuiot/lamassuiot/pkg/alerts/server/config"
)

func BuildCATestServer() (*httptest.Server, *caService.Service, error) {
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
		return nil, nil, err
	}

	certificateRepository := caRepository.NewPostgresDB(db, logger)
	tracer := opentracing.NoopTracer{}
	os.Mkdir("/tmp/tests", 0755)
	engine, _ := cryptoEngines.NewGolangPEMEngine(logger, "/tmp/tests")
	var svc caService.Service
	svc = caService.NewCAService(logger, engine, certificateRepository, "http://ocsp.test")
	//svc = caService.LoggingMiddleware(logger)(svc)

	handler := caTransport.MakeHTTPHandler(svc, logger, tracer)

	mux := http.NewServeMux()
	mux.Handle("/v1/", http.StripPrefix("/v1", handler))
	server := httptest.NewUnstartedServer(mux)

	return server, &svc, nil
}

func BuildDMSManagerTestServer(CATestServer *httptest.Server) (*httptest.Server, *dmsService.Service, error) {
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
		return nil, nil, err
	}

	dmsRepository := dmsRepository.NewPostgresDB(db, logger)
	tracer := opentracing.NoopTracer{}

	CATestServerURL, err := url.Parse(CATestServer.URL)
	if err != nil {
		return nil, nil, err
	}

	lamassuCAClient, err := caClient.NewLamassuCAClient(clientUtils.BaseClientConfigurationuration{
		URL:        CATestServerURL,
		AuthMethod: clientUtils.AuthMethodNone,
	})
	if err != nil {
		return nil, nil, err
	}

	var svc dmsService.Service
	svc = dmsService.NewDMSManagerService(logger, dmsRepository, &lamassuCAClient)
	svc = dmsService.LoggingMiddleware(logger)(svc)

	handler := dmsTransport.MakeHTTPHandler(svc, logger, tracer)

	mux := http.NewServeMux()
	mux.Handle("/v1/", http.StripPrefix("/v1", handler))
	server := httptest.NewUnstartedServer(mux)

	return server, &svc, nil
}

func BuildDeviceManagerTestServer(CATestServer *httptest.Server, DMSTestServer *httptest.Server) (*httptest.Server, *deviceService.Service, error) {
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
		return nil, nil, err
	}

	deviceRepository := postgresRepository.NewDevicesPostgresDB(db, logger)
	tracer := opentracing.NoopTracer{}

	CATestServerURL, err := url.Parse(CATestServer.URL)
	if err != nil {
		return nil, nil, err
	}

	lamassuCAClient, err := caClient.NewLamassuCAClient(clientUtils.BaseClientConfigurationuration{
		URL:        CATestServerURL,
		AuthMethod: clientUtils.AuthMethodNone,
	})
	if err != nil {
		return nil, nil, err
	}

	DMSTestServerURL, err := url.Parse(DMSTestServer.URL)
	if err != nil {
		return nil, nil, err
	}
	lamassuDMSClient, err := dmsClient.NewLamassuDMSManagerClientConfig(clientUtils.BaseClientConfigurationuration{
		URL:        DMSTestServerURL,
		AuthMethod: clientUtils.AuthMethodNone,
	})
	if err != nil {
		return nil, nil, err
	}

	statsRepo, err := deviceStatsRepository.NewStatisticsDBInMemory()
	if err != nil {
		return nil, nil, err
	}
	logsRepo := postgresRepository.NewLogsPostgresDB(db, logger)
	if err != nil {
		return nil, nil, err
	}
	svc := deviceService.NewDeviceManagerService(logger, deviceRepository, logsRepo, statsRepo, 30, lamassuCAClient, lamassuDMSClient)
	svc = deviceService.LoggingMiddleware(logger)(svc)

	handler := deviceTransport.MakeHTTPHandler(svc, logger, tracer)
	estHandler := estTransport.MakeHTTPHandler(svc, logger, tracer)

	mux := http.NewServeMux()
	mux.Handle("/v1/", http.StripPrefix("/v1", handler))
	mux.Handle("/.well-known/", estHandler)
	server := httptest.NewUnstartedServer(mux)

	return server, &svc, nil
}

func BuildOCSPTestServer(CATestServer *httptest.Server) (*httptest.Server, error) {
	var logger log.Logger

	logger = log.NewNopLogger()
	logger = level.NewFilter(logger, level.AllowDebug())
	logger = log.With(logger, "ts", log.DefaultTimestampUTC)
	logger = log.With(logger, "caller", log.DefaultCaller)

	tracer := opentracing.NoopTracer{}

	CATestServerURL, err := url.Parse(CATestServer.URL)
	if err != nil {
		return nil, err
	}

	lamassuCAClient, err := caClient.NewLamassuCAClient(clientUtils.BaseClientConfigurationuration{
		URL:        CATestServerURL,
		AuthMethod: clientUtils.AuthMethodNone,
	})
	if err != nil {
		return nil, err
	}

	ocspSigner, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"ES"},
			Locality:     []string{"Donostia"},
			Organization: []string{"LAMASSU Foundation"},
			CommonName:   "LAMASSU OCSP",
		},
	}

	crtBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, ocspSigner.Public(), ocspSigner)
	if err != nil {
		panic(err)
	}

	ocspCertificate, err := x509.ParseCertificate(crtBytes)
	if err != nil {
		panic(err)
	}

	svc := ocspService.NewOCSPService(lamassuCAClient, ocspSigner, ocspCertificate)

	handler := ocspTransport.MakeHTTPHandler(svc, logger, false, tracer)

	mux := http.NewServeMux()
	mux.Handle("/", handler)
	server := httptest.NewUnstartedServer(mux)

	return server, nil
}

func BuildMailTestServer(jsonTemplate string, smtpConfig outputchannels.SMTPOutputService) (*httptest.Server, error) {

	var logger log.Logger

	logger = log.NewNopLogger()
	logger = level.NewFilter(logger, level.AllowDebug())
	logger = log.With(logger, "ts", log.DefaultTimestampUTC)
	logger = log.With(logger, "caller", log.DefaultCaller)

	tracer := opentracing.NoopTracer{}

	config := config.NewMailConfig()
	mainServer := server.NewServer(config)

	//dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable", config.PostgresHostname, config.PostgresUser, config.PostgresPassword, config.PostgresDatabase, config.PostgresPort)

	dialector := sqlite.Open("")
	db, err := gorm.Open(dialector, &gorm.Config{
		Logger: gormLogger.Default.LogMode(gormLogger.Silent),
	})
	if err != nil {
		level.Error(mainServer.Logger).Log("msg", "Could not connect to Postgres", "err", err)
		os.Exit(1)
	}

	if err != nil {
		return nil, err
	}

	mailRepo := alertsRepository.NewPostgresDB(db, logger)

	var svc alertsService.Service
	svc, err = service.NewAlertsService(logger, mailRepo, jsonTemplate, smtpConfig)
	if err != nil {
		return nil, err
	}
	handler := alertsTransport.MakeHTTPHandler(svc, logger, tracer)

	mux := http.NewServeMux()
	mux.Handle("/", handler)
	server := httptest.NewUnstartedServer(mux)

	return server, nil
}
