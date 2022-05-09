package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	migrate "github.com/golang-migrate/migrate/v4"
	migratePostgres "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/hashicorp/consul/api"
	lamassucaclient "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	clientUtils "github.com/lamassuiot/lamassuiot/pkg/utils/client"

	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/api/transport"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/cloud-providers/store"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/cloud-providers/store/db"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/config"
	"github.com/lamassuiot/lamassuiot/pkg/utils"
	"github.com/opentracing/opentracing-go"

	jaegercfg "github.com/uber/jaeger-client-go/config"
	jaegerlog "github.com/uber/jaeger-client-go/log"
)

func main() {

	var logger log.Logger
	logger = log.NewJSONLogger(os.Stdout)
	logger = level.NewFilter(logger, level.AllowDebug())
	logger = log.With(logger, "ts", log.DefaultTimestampUTC)
	logger = log.With(logger, "caller", log.DefaultCaller)

	cfg, err := config.NewConfig("")
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not read environment configuration values")
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Environment configuration values loaded")

	tracer, tracerCloser := initializeJaeger(logger)
	defer tracerCloser.Close()
	opentracing.SetGlobalTracer(tracer)

	cloudProxyDb := initializeDB(cfg.PostgresDB, cfg.PostgresUser, cfg.PostgresPassword, cfg.PostgresHostname, cfg.PostgresPort, cfg.PostgresMigrationsFilePath, logger)

	consulClient := initializeConsulClient(cfg.ConsulProtocol, cfg.ConsulHost, cfg.ConsulPort, cfg.ConsulCA, logger)

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

	var s service.Service
	{
		s = service.NewCloudPorxyService(consulClient, cloudProxyDb, lamassuCaClient, logger)
		s = service.LoggingMiddleware(logger)(s)
	}

	// mux := http.NewServeMux()
	http.Handle("/v1/", accessControl(http.StripPrefix("/v1", transport.MakeHTTPHandler(s, log.With(logger, "component", "HTTPS"), tracer))))

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

	transport.MakeAmqpHandler(s, logger, tracer, cfg.AmqpServerCaCert, cfg.AmqpClientCert, cfg.AmqpClientKey, cfg.AmqpServerHost, cfg.AmqpServerPort)

	level.Info(logger).Log("exit", <-errs)
}

func initializeJaeger(logger log.Logger) (opentracing.Tracer, io.Closer) {
	jcfg, err := jaegercfg.FromEnv()
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not load Jaeger configuration values fron environment")
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Jaeger configuration values loaded")

	tracer, closer, err := jcfg.NewTracer(
		jaegercfg.Logger(jaegerlog.StdLogger),
	)

	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not start Jaeger tracer")
		os.Exit(1)
	}

	level.Info(logger).Log("msg", "Jaeger tracer started")

	return tracer, closer
}

func initializeDB(database string, user string, password string, hostname string, port string, migrationsFilePath string, logger log.Logger) store.DB {
	devicesConnStr := "dbname=" + database + " user=" + user + " password=" + password + " host=" + hostname + " port=" + port + " sslmode=disable"
	cloudProxyStore, err := db.NewDB("postgres", devicesConnStr, logger)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not start connection with database. Will sleep for 5 seconds and exit the program")
		time.Sleep(5 * time.Second)
		os.Exit(1)
	}

	level.Info(logger).Log("msg", "Connection established with Devices database")

	level.Info(logger).Log("msg", "Checking if DB migration is required")

	cloudProxyDb := cloudProxyStore.(*db.DB)
	driver, err := migratePostgres.WithInstance(cloudProxyDb.DB, &migratePostgres.Config{})
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

	mLogger := utils.NewGoKitLogToGoLogAdapter(logger)

	m.Log = mLogger

	m.Up()
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not perform db migration")
		os.Exit(1)
	}

	return cloudProxyStore
}

func initializeConsulClient(consulProtocol string, consulHost string, consulPort string, consulCA string, logger log.Logger) *api.Client {
	consulConfig := api.DefaultConfig()
	if consulProtocol == "https" || consulProtocol == "http" {
		if (consulProtocol == "https" && consulPort == "443") || (consulProtocol == "http" && consulPort == "80") {
			consulConfig.Address = consulProtocol + "://" + consulHost
		} else {
			consulConfig.Address = consulProtocol + "://" + consulHost + ":" + consulPort
		}
	} else {
		level.Error(logger).Log("msg", "Unsuported consul protocol")
	}
	tlsConf := &api.TLSConfig{CAFile: consulCA}
	consulConfig.TLSConfig = *tlsConf
	consulClient, err := api.NewClient(consulConfig)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not start Consul API Client")
		os.Exit(1)
	}

	agent := consulClient

	level.Info(logger).Log("msg", "Connection established with Consul")

	return agent
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
