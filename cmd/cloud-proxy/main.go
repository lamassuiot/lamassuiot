package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/hashicorp/consul/api"
	lamassucaclient "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	clientUtils "github.com/lamassuiot/lamassuiot/pkg/utils/client"
	serverUtils "github.com/lamassuiot/lamassuiot/pkg/utils/server"

	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/api/transport"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/cloud-providers/store/db"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/config"
	"github.com/lamassuiot/lamassuiot/pkg/utils"
	"github.com/opentracing/opentracing-go"

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

	cfg, err := config.NewConfig("")
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not read environment configuration values")
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Environment configuration values loaded")

	tracer, tracerCloser := initializeJaeger(logger)
	defer tracerCloser.Close()
	opentracing.SetGlobalTracer(tracer)

	cloudProxyRawDB, err := serverUtils.InitializeDBConnection(cfg.PostgresDB, cfg.PostgresUser, cfg.PostgresPassword, cfg.PostgresHostname, cfg.PostgresPort, true, cfg.PostgresMigrationsFilePath, logger)
	if err != nil {
		os.Exit(1)
	}

	cloudProxyDB := db.NewDB(cloudProxyRawDB, logger)
	consulClient := initializeConsulClient(cfg.ConsulProtocol, cfg.ConsulHost, cfg.ConsulPort, cfg.ConsulCA, logger)

	lamassuCaClient, err := lamassucaclient.NewLamassuCAClient(clientUtils.ClientConfiguration{
		URL: &url.URL{
			Scheme: "https",
			Host:   cfg.LamassuCAAddress,
		},
		AuthMethod: clientUtils.MutualTLS,
		AuthMethodConfig: &clientUtils.MutualTLSConfig{
			ClientCert: cfg.LamassuCAClientCertFile,
			ClientKey:  cfg.LamassuCAClientKeyFile,
		},
		CACertificate: cfg.LamassuCACertFile,
	})

	var s service.Service
	{
		s = service.NewCloudPorxyService(consulClient, cloudProxyDB, lamassuCaClient, logger)
		s = service.LoggingMiddleware(logger)(s)
	}

	// mux := http.NewServeMux()
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
