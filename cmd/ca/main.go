package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	"github.com/go-openapi/runtime/middleware"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	_ "github.com/golang-migrate/migrate/v4/source/file"
	gormLogger "gorm.io/gorm/logger"

	postgresRepository "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/repository/postgres"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service"
	cryptoEngines "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service/crypto-engines"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/transport"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/config"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/docs"

	serverUtils "github.com/lamassuiot/lamassuiot/pkg/utils/server"
	"github.com/opentracing/opentracing-go"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/streadway/amqp"
	jaegercfg "github.com/uber/jaeger-client-go/config"
	jaegerlog "github.com/uber/jaeger-client-go/log"
)

var (
	sha1ver   string // sha1 revision used to build the program
	buildTime string // when the executable was built
)

func main() {

	var logger log.Logger
	logger = log.NewJSONLogger(os.Stdout)
	logger = level.NewFilter(logger, level.AllowDebug())
	logger = log.With(logger, "ts", log.DefaultTimestampUTC)
	logger = log.With(logger, "caller", log.DefaultCaller)

	/*********************************************************************/

	cfg, err := config.NewConfig("")
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not read environment configuration values")
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Environment configuration values loaded")

	if strings.ToLower(cfg.DebugMode) == "debug" {
		logger = level.NewFilter(logger, level.AllowDebug())
		level.Debug(logger).Log("msg", "Starting in debug mode...")
	}

	engine, err := cryptoEngines.NewHSMPEngine(logger, "/home/ikerlan/pkcs11-proxy/libpkcs11-proxy.so.0.1", "lamassuHSM", "1234")
	if err != nil {
		panic(err)
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

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable", cfg.PostgresHostname, cfg.PostgresUser, cfg.PostgresPassword, cfg.PostgresDatabase, cfg.PostgresPort)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: gormLogger.Default.LogMode(gormLogger.Silent),
	})
	if err != nil {
		panic(err)
	}

	certificateRepository := postgresRepository.NewPostgresDB(db, logger)

	amq_cfg := new(tls.Config)
	amq_cfg.RootCAs = x509.NewCertPool()

	if ca, err := ioutil.ReadFile(cfg.AmqpServerCACertFile); err == nil {
		amq_cfg.RootCAs.AppendCertsFromPEM(ca)
	}
	if cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile); err == nil {
		amq_cfg.Certificates = append(amq_cfg.Certificates, cert)
	}

	amqpConn, err := amqp.DialTLS("amqps://"+cfg.AmqpIP+":"+cfg.AmqpPort+"", amq_cfg)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Failed to connect to AMQP")
		os.Exit(1)
	}
	defer amqpConn.Close()

	amqpChannel, err := amqpConn.Channel()
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Failed to create AMQP channel")
		os.Exit(1)
	}
	defer amqpChannel.Close()

	fieldKeys := []string{"method", "error"}

	var s service.Service
	{
		s = service.NewCAService(logger, engine, certificateRepository, cfg.OcspUrl)
		// s = service.NewAmqpMiddleware(amqpChannel, logger)(s)
		s = service.LoggingMiddleware(logger)(s)
		s = service.NewInstrumentingMiddleware(
			kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
				Namespace: "ca",
				Subsystem: "ca_service",
				Name:      "request_count",
				Help:      "Number of requests received.",
			}, fieldKeys),
			kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
				Namespace: "ca",
				Subsystem: "ca_service",
				Name:      "request_latency_microseconds",
				Help:      "Total duration of requests in microseconds.",
			}, fieldKeys),
		)(s)
	}

	openapiSpec := docs.NewOpenAPI3(cfg)

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

	mux := http.NewServeMux()
	infoHandler := func() http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			info := struct {
				BuildVersion string `json:"build_version"`
				BuildTime    string `json:"build_time"`
			}{
				BuildVersion: sha1ver,
				BuildTime:    buildTime,
			}
			infoData, _ := json.Marshal(&info)
			w.Header().Add("content-type", "application/json; charset=utf-8")
			w.Write(infoData)
		}
	}

	http.Handle("/info", accessControl(infoHandler()))
	http.Handle("/v1/", accessControl(http.StripPrefix("/v1", transport.MakeHTTPHandler(s, log.With(logger, "component", "HTTPS"), tracer))))
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
		serverCfg := serverUtils.ServerConfiguration{
			Port:              cfg.Port,
			Protocol:          cfg.Protocol,
			CertFile:          cfg.CertFile,
			KeyFile:           cfg.KeyFile,
			MutualTLSEnabled:  cfg.MutualTLSEnabled,
			MutualTLSClientCA: cfg.MutualTLSClientCA,
		}

		serverCfg.RunServer(logger, errs)
	}()

	level.Info(logger).Log("exit", <-errs)
}

func accessControl(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// dumpReq, err := httputil.DumpRequest(r, true)
		// if err == nil {
		// 	fmt.Println(string(dumpReq))
		// }

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			return
		}

		h.ServeHTTP(w, r)
	})
}
