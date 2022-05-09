package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	"github.com/go-openapi/runtime/middleware"

	migrate "github.com/golang-migrate/migrate/v4"
	migratePostgres "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"

	lamassucaclient "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/transport"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/configs"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/docs"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/estserver"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/models/device/store"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/models/device/store/db"
	dmsDb "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/models/dms/store/db"
	verify "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/utils"
	"github.com/lamassuiot/lamassuiot/pkg/utils"
	clientUtils "github.com/lamassuiot/lamassuiot/pkg/utils/client"
	"github.com/opentracing/opentracing-go"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	jaegercfg "github.com/uber/jaeger-client-go/config"
	jaegerlog "github.com/uber/jaeger-client-go/log"
)

func main() {
	var logger log.Logger
	{
		logger = log.NewJSONLogger(os.Stdout)
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		logger = level.NewFilter(logger, level.AllowInfo())
		logger = log.With(logger, "caller", log.DefaultCaller)
	}

	err, cfg := configs.NewConfig("")
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not read environment configuration values")
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Environment configuration values loaded")

	if strings.ToLower(cfg.DebugMode) == "debug" {
		{
			logger = log.NewJSONLogger(os.Stdout)
			logger = log.With(logger, "ts", log.DefaultTimestampUTC)
			logger = level.NewFilter(logger, level.AllowDebug())
			logger = log.With(logger, "caller", log.DefaultCaller)
		}
		level.Debug(logger).Log("msg", "Starting Lamassu-Device-Manager in debug mode...")
	}

	jcfg, err := jaegercfg.FromEnv()
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not load Jaeger configuration values fron environment")
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Jaeger configuration values loaded")
	tracer, closer, err := jcfg.NewTracer(
		jaegercfg.Logger(jaegerlog.StdLogger),
	)
	opentracing.SetGlobalTracer(tracer)

	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not start Jaeger tracer")
		os.Exit(1)
	}
	defer closer.Close()
	level.Info(logger).Log("msg", "Jaeger tracer started")

	devicesDb := initializeDB(cfg.PostgresDevicesDB, cfg.PostgresUser, cfg.PostgresPassword, cfg.PostgresHostname, cfg.PostgresPort, cfg.PostgresMigrationsFilePath, logger)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not start connection with Devices database. Will sleep for 5 seconds and exit the program")
		time.Sleep(5 * time.Second)
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Connection established with Devices database")

	dmsConnStr := "dbname=" + cfg.PostgresDmsDB + " user=" + cfg.PostgresUser + " password=" + cfg.PostgresPassword + " host=" + cfg.PostgresHostname + " port=" + cfg.PostgresPort + " sslmode=disable"
	dmsDb, err := dmsDb.NewDB("postgres", dmsConnStr, logger)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not start connection with DMS database. Will sleep for 5 seconds and exit the program")
		time.Sleep(5 * time.Second)
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Connection established with DMS database")

	fieldKeys := []string{"method", "error"}

	lamassuCaClient, err := lamassucaclient.NewLamassuCAClient(clientUtils.ClientConfiguration{
		URL: &url.URL{
			Scheme: "https",
			Host:   cfg.LamassuCAAddress,
		},
		AuthMethod: clientUtils.MutualTLS,
		AuthMethodConfig: &clientUtils.MutualTLSConfig{
			ClientCert: cfg.CertFile,
			ClientKey:  cfg.KeyFile,
		},
		CACertificate: cfg.LamassuCACertFile,
	})
	if err != nil {
		level.Error(logger).Log("err", err)
		os.Exit(1)
	}
	verify := verify.NewUtils(&lamassuCaClient, logger)

	var s service.Service
	{
		s = service.NewDevicesService(devicesDb, &lamassuCaClient, logger)
		s = service.LoggingMiddleware(logger)(s)
		s = service.NewInstrumentingMiddleware(
			kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
				Namespace: "enroller",
				Subsystem: "enroller_service",
				Name:      "request_count",
				Help:      "Number of requests received.",
			}, fieldKeys),
			kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
				Namespace: "enroller",
				Subsystem: "enroller_service",
				Name:      "request_latency_microseconds",
				Help:      "Total duration of requests in microseconds.",
			}, fieldKeys),
		)(s)
	}
	openapiSpec := docs.NewOpenAPI3(cfg)
	err = os.MkdirAll("docs", 0744)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not create openapiv3 docs dir")
		os.Exit(1)
	}

	var ctx context.Context
	mux := http.NewServeMux()
	minimumReenrollDays, err := strconv.Atoi(cfg.MinimumReenrollDays)
	estService := estserver.NewEstService(&lamassuCaClient, &verify, devicesDb, dmsDb, minimumReenrollDays, logger)

	specHandler := func(prefix string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			url := r.URL.Path
			if originalPrefix, ok := r.Header["X-Envoy-Original-Path"]; ok {
				url = originalPrefix[0]
			}
			url = strings.Split(url, prefix)[0]
			openapiSpec.Servers[0].URL = url
			openapiSpecJsonData, _ := json.Marshal(&openapiSpec)
			w.Write(openapiSpecJsonData)
		}
	}

	http.Handle("/.well-known/", accessControl(estserver.MakeHTTPHandler(estService, verify, log.With(logger, "component", "HTTPS"), cfg, tracer, ctx)))
	http.Handle("/v1/", accessControl(transport.MakeHTTPHandler(s, log.With(logger, "component", "HTTPS"), tracer)))
	http.Handle("/v1/docs/", http.StripPrefix("/v1/docs", middleware.SwaggerUI(middleware.SwaggerUIOpts{
		Path:    "/",
		SpecURL: "spec.json",
	}, mux)))
	http.HandleFunc("/v1/docs/spec.json", specHandler("/v1/docs/"))
	http.Handle("/metrics", promhttp.Handler())

	errs := make(chan error)
	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errs <- fmt.Errorf("%s", <-c)
	}()

	go func() {
		if strings.ToLower(cfg.Protocol) == "https" {
			if cfg.MutualTLSEnabled {
				mTlsCertPool, err := utils.CreateCAPool(cfg.MutualTLSClientCA)
				if err != nil {
					level.Error(logger).Log("err", err, "msg", "Could not create mTls Cert Pool")
					os.Exit(1)
				}
				tlsConfig := &tls.Config{
					ClientCAs:  mTlsCertPool,
					ClientAuth: tls.RequireAndVerifyClientCert,
				}

				tlsConfig.BuildNameToCertificate()

				http := &http.Server{
					Addr:      ":" + cfg.Port,
					TLSConfig: tlsConfig,
				}

				level.Info(logger).Log("transport", "Mutual TLS", "address", ":"+cfg.Port, "msg", "listening")
				errs <- http.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile)

			} else {
				level.Info(logger).Log("transport", "HTTPS", "address", ":"+cfg.Port, "msg", "listening")
				errs <- http.ListenAndServeTLS(":"+cfg.Port, cfg.CertFile, cfg.KeyFile, nil)

			}
		} else if strings.ToLower(cfg.Protocol) == "http" {
			level.Info(logger).Log("transport", "HTTP", "address", ":"+cfg.Port, "msg", "listening")
			errs <- http.ListenAndServe(":"+cfg.Port, nil)

		} else {
			level.Error(logger).Log("err", "msg", "Unknown protocol")
			os.Exit(1)

		}
	}()
	level.Info(logger).Log("exit", <-errs)
}

func accessControl(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			return
		}

		h.ServeHTTP(w, r)
	})
}
func initializeDB(database string, user string, password string, hostname string, port string, migrationsFilePath string, logger log.Logger) store.DB {
	devicesConnStr := "dbname=" + database + " user=" + user + " password=" + password + " host=" + hostname + " port=" + port + " sslmode=disable"
	devicesStore, err := db.NewDB("postgres", devicesConnStr, logger)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not start connection with database. Will sleep for 5 seconds and exit the program")
		time.Sleep(5 * time.Second)
		os.Exit(1)
	}

	level.Info(logger).Log("msg", "Connection established with Devices database")

	level.Info(logger).Log("msg", "Checking if DB migration is required")

	devicesDb := devicesStore.(*db.DB)
	driver, err := migratePostgres.WithInstance(devicesDb.DB, &migratePostgres.Config{})
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not create postgres migration driver")
		os.Exit(1)
	}
	m, err := migrate.NewWithDatabaseInstance(
		"file://"+migrationsFilePath,
		"postgres", driver)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not create db migration instance ")
		os.Exit(1)
	}

	m.Up()
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not perform db migration")
		os.Exit(1)
	}
	return devicesStore
}
