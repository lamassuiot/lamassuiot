package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/kelseyhightower/envconfig"
	"github.com/opentracing/opentracing-go"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/streadway/amqp"
	jaegercfg "github.com/uber/jaeger-client-go/config"
	jaegerlog "github.com/uber/jaeger-client-go/log"
)

var (
	sha1ver   string = "test"              // sha1 revision used to build the program
	buildTime string = time.Now().String() // when the executable was built
)

type Configuration interface {
	GetBaseConfiguration() *BaseConfiguration
	GetConfiguration() interface{}
}

type BaseConfiguration struct {
	DebugMode         bool   `required:"true" split_words:"true"`
	Port              string `required:"true" split_words:"true"`
	Protocol          string `required:"true" split_words:"true"`
	CertFile          string `required:"true" split_words:"true"`
	KeyFile           string `required:"true" split_words:"true"`
	MutualTLSEnabled  bool   `required:"true" split_words:"true"`
	MutualTLSClientCA string `required:"true" split_words:"true"`
	AmqpServerHost    string `required:"true" split_words:"true"`
	AmqpServerPort    string `required:"true" split_words:"true"`
	AmqpServerCACert  string `required:"true" split_words:"true"`
}

type Server struct {
	Logger      log.Logger
	Tracer      opentracing.Tracer
	AmqpChannel *amqp.Channel
	cfg         *BaseConfiguration
	mux         *http.ServeMux
}

func NewServer(config Configuration) *Server {
	var logger log.Logger
	logger = log.NewJSONLogger(os.Stdout)
	logger = log.With(logger, "ts", log.DefaultTimestampUTC)

	err := envconfig.Process("", config.GetConfiguration())
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not process configuration")
		os.Exit(1)
	}

	baseConfig := config.GetBaseConfiguration()

	if baseConfig.DebugMode {
		logger = level.NewFilter(logger, level.AllowDebug())
		level.Debug(logger).Log("msg", "Starting in debug mode...")
	}
	logger = log.With(logger, "caller", log.DefaultCaller)

	mux := http.NewServeMux()

	http.Handle("/info", accessControl(infoHandler()))
	http.Handle("/metrics", promhttp.Handler())

	s := Server{
		Logger: logger,
		cfg:    baseConfig,
		mux:    mux,
	}

	s.startJaegerTracer()

	return &s
}

func (s *Server) AddHttpHandler(path string, handler http.Handler) {
	http.Handle(path, accessControl(handler))
}

func (s *Server) AddHttpFuncHandler(path string, handler func(http.ResponseWriter, *http.Request)) {
	http.HandleFunc(path, handler)
}

func (s *Server) Run(errorsChannel chan error) {
	amq_cfg := tls.Config{}
	amq_cfg.RootCAs = x509.NewCertPool()

	ca, err := ioutil.ReadFile(s.cfg.AmqpServerCACert)
	if err != nil {
		level.Error(s.Logger).Log("err", err, "msg", "Could not read AMQP CA certificate")
		os.Exit(1)
	}

	amq_cfg.RootCAs.AppendCertsFromPEM(ca)
	cert, err := tls.LoadX509KeyPair(s.cfg.CertFile, s.cfg.KeyFile)

	if err != nil {
		level.Error(s.Logger).Log("err", err, "msg", "Could not load AMQP TLS certificate")
		os.Exit(1)
	}

	amq_cfg.Certificates = append(amq_cfg.Certificates, cert)
	amqpConn, err := amqp.DialTLS("amqps://"+s.cfg.AmqpServerHost+":"+s.cfg.AmqpServerPort+"", &amq_cfg)
	if err != nil {
		level.Error(s.Logger).Log("err", err, "msg", "Failed to connect to AMQP")
		os.Exit(1)
	}
	defer amqpConn.Close()

	amqpChannel, err := amqpConn.Channel()
	if err != nil {
		level.Error(s.Logger).Log("err", err, "msg", "Failed to create AMQP channel")
		os.Exit(1)
	}
	s.AmqpChannel = amqpChannel
	defer amqpChannel.Close()

	go func() {
		if strings.ToLower(s.cfg.Protocol) == "https" {
			if s.cfg.MutualTLSEnabled {
				mTlsCertPool := x509.NewCertPool()
				caCert, err := ioutil.ReadFile(s.cfg.MutualTLSClientCA)
				if err != nil {
					level.Error(s.Logger).Log("err", err, "msg", "Could not read client CA file")
					os.Exit(1)
				}

				if !mTlsCertPool.AppendCertsFromPEM(caCert) {
					level.Error(s.Logger).Log("msg", "Could not append client CA to cert pool")
					os.Exit(1)
				}

				tlsConfig := &tls.Config{
					ClientCAs:  mTlsCertPool,
					ClientAuth: tls.RequireAndVerifyClientCert,
				}

				http := &http.Server{
					Addr:      ":" + s.cfg.Port,
					TLSConfig: tlsConfig,
				}

				level.Info(s.Logger).Log("transport", "Mutual TLS", "address", ":"+s.cfg.Port, "msg", "listening")
				errorsChannel <- http.ListenAndServeTLS(s.cfg.CertFile, s.cfg.KeyFile)

			} else {
				level.Info(s.Logger).Log("transport", "HTTPS", "address", ":"+s.cfg.Port, "msg", "listening")
				errorsChannel <- http.ListenAndServeTLS(":"+s.cfg.Port, s.cfg.CertFile, s.cfg.KeyFile, nil)
			}
		} else if strings.ToLower(s.cfg.Protocol) == "http" {
			level.Info(s.Logger).Log("transport", "HTTP", "address", ":"+s.cfg.Port, "msg", "listening")
			errorsChannel <- http.ListenAndServe(":"+s.cfg.Port, nil)
		} else {
			level.Error(s.Logger).Log("err", "msg", "Unknown protocol")
			os.Exit(1)
		}
	}()
}

func (s *Server) startJaegerTracer() {
	jcfg, err := jaegercfg.FromEnv()
	if err != nil {
		level.Error(s.Logger).Log("err", err, "msg", "Could not load Jaeger configuration values fron environment")
		os.Exit(1)
	}
	level.Info(s.Logger).Log("msg", "Jaeger configuration values loaded")

	tracer, _, err := jcfg.NewTracer(
		jaegercfg.Logger(jaegerlog.StdLogger),
	)
	opentracing.SetGlobalTracer(tracer)

	if err != nil {
		level.Error(s.Logger).Log("err", err, "msg", "Could not start Jaeger tracer")
		os.Exit(1)
	}

	level.Info(s.Logger).Log("msg", "Jaeger tracer started")
	s.Tracer = tracer
}

func infoHandler() http.HandlerFunc {
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
