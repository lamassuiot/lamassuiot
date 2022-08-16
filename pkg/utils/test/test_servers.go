package tests

import (
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/opentracing/opentracing-go"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"

	clientUtils "github.com/lamassuiot/lamassuiot/pkg/utils/client"

	caClient "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	caRepository "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/repository/postgres"
	caService "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service"
	cryptoEngines "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service/crypto-engines"
	caTransport "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/transport"

	dmsClient "github.com/lamassuiot/lamassuiot/pkg/dms-manager/client"
	dmsRepository "github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/repository/postgres"
	dmsService "github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/service"
	dmsTransport "github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/transport"

	deviceRepository "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/repository/postgres"
	deviceService "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/service"
	deviceTransport "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/transport"

	estTransport "github.com/lamassuiot/lamassuiot/pkg/est/server/api/transport"
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

	engine, _ := cryptoEngines.NewGolangPEMEngine(logger, "/tmp/tests")
	var svc caService.Service
	svc = caService.NewCAService(logger, engine, certificateRepository, "http://ocsp.test")
	svc = caService.LoggingMiddleware(logger)(svc)

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

	lamassuCAClient, err := caClient.NewLamassuCAClient(clientUtils.ClientConfiguration{
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

	deviceRepository := deviceRepository.NewDevicesPostgresDB(db, logger)
	tracer := opentracing.NoopTracer{}

	CATestServerURL, err := url.Parse(CATestServer.URL)
	if err != nil {
		return nil, nil, err
	}

	lamassuCAClient, err := caClient.NewLamassuCAClient(clientUtils.ClientConfiguration{
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
	lamassuDMSClient, err := dmsClient.NewLamassuDMSManagerClientConfig(clientUtils.ClientConfiguration{
		URL:        DMSTestServerURL,
		AuthMethod: clientUtils.AuthMethodNone,
	})
	if err != nil {
		return nil, nil, err
	}

	var svc deviceService.Service
	svc = deviceService.NewDeviceManagerService(logger, deviceRepository, nil, nil, 30, lamassuCAClient, lamassuDMSClient)
	// svc = deviceService.LoggingMiddleware(logger)(svc)

	handler := deviceTransport.MakeHTTPHandler(svc, logger, tracer)
	estHandler := estTransport.MakeHTTPHandler(svc, logger, tracer)

	mux := http.NewServeMux()
	mux.Handle("/v1/", http.StripPrefix("/v1", handler))
	mux.Handle("/.well-known/", estHandler)
	server := httptest.NewUnstartedServer(mux)

	return server, &svc, nil
}
