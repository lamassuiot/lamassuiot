package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel"

	// stdout "go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/jaeger"
	semconv "go.opentelemetry.io/otel/semconv/v1.12.0"

	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	amqptransport "github.com/go-kit/kit/transport/amqp"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/kelseyhightower/envconfig"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/streadway/amqp"
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
	ServiceName           string `required:"true" split_words:"true"`
	DeploymentEnvironment string `required:"true" split_words:"true"`
	JaegerExporterURL     string `required:"true" split_words:"true"`
	DebugMode             bool   `required:"true" split_words:"true"`
	Port                  string `required:"true" split_words:"true"`
	Protocol              string `required:"true" split_words:"true"`
	CertFile              string `required:"true" split_words:"true"`
	KeyFile               string `required:"true" split_words:"true"`
	MutualTLSEnabled      bool   `required:"true" split_words:"true"`
	MutualTLSClientCA     string `required:"true" split_words:"true"`
	AmqpServerHost        string `required:"true" split_words:"true"`
	AmqpServerPort        string `required:"true" split_words:"true"`
	AmqpServerCACert      string `required:"true" split_words:"true"`
}

type AmqpPublishMessage struct {
	Exchange  string
	Key       string
	Mandatory bool
	Immediate bool
	Msg       amqp.Publishing
}

type Server struct {
	Logger        log.Logger
	cfg           *BaseConfiguration
	mux           *http.ServeMux
	amqpConsumers map[string]*amqptransport.Subscriber //map queuName to amqptransport.Subscriber
	AmqpPublisher chan AmqpPublishMessage
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
		Logger:        logger,
		cfg:           baseConfig,
		mux:           mux,
		amqpConsumers: map[string]*amqptransport.Subscriber{},
		AmqpPublisher: make(chan AmqpPublishMessage),
	}

	s.initTracer()

	return &s
}

func (s *Server) AddAmqpConsumer(queuName string, subscriber *amqptransport.Subscriber) {
	s.amqpConsumers[queuName] = subscriber
}

func (s *Server) AddHttpHandler(path string, handler http.Handler) {
	http.Handle(path /*otelhttp.NewHandler(*/, accessControl(handler) /*, path)*/)
}

func (s *Server) AddHttpFuncHandler(path string, handler func(http.ResponseWriter, *http.Request)) {
	http.HandleFunc(path, handler)
}

func (s *Server) Run(errorsChannel chan error) {
	go func() {
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
		// defer amqpConn.Close()

		amqpChannel, err := amqpConn.Channel()
		if err != nil {
			level.Error(s.Logger).Log("err", err, "msg", "Failed to create AMQP channel")
			os.Exit(1)
		}
		// defer amqpChannel.Close()

		for queueName, subscriber := range s.amqpConsumers {
			consumerQueue, err := amqpChannel.QueueDeclare(queueName, true, false, false, false, nil)
			if err != nil {
				level.Error(s.Logger).Log("err", err, "msg", fmt.Sprintf("Failed to create AMQP %s queue", queueName))
				os.Exit(1)
			}

			msgDelivery, err := amqpChannel.Consume(consumerQueue.Name, fmt.Sprintf("test-consumer-%s", queueName), true, false, false, false, nil)
			if err != nil {
				level.Error(s.Logger).Log("err", err, "msg", fmt.Sprintf("Failed to consume AMQP %s queue", queueName))
				os.Exit(1)
			}

			msgHandler := subscriber.ServeDelivery(amqpChannel)

			go func() {
				for {
					select {
					case msg := <-msgDelivery:
						msgHandler(&msg)
					}
				}
			}()

			level.Info(s.Logger).Log("msg", fmt.Sprintf("Waiting messages for queue %s", queueName))
		}

		go func() {
			for {
				select {
				case amqpMessage := <-s.AmqpPublisher:
					amqpErr := amqpChannel.Publish(amqpMessage.Exchange, amqpMessage.Key, amqpMessage.Mandatory, amqpMessage.Immediate, amqpMessage.Msg)
					if amqpErr != nil {
						level.Error(s.Logger).Log("msg", "Error while publishing to AMQP queue", "err", amqpErr)
					}
				}
			}
		}()

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

	}()
}

func (s *Server) initTracer() {
	// exporter, err := stdout.New(stdout.WithPrettyPrint())
	// if err != nil {
	// 	level.Error(s.Logger).Log("err", err, "msg", "Could not create stdout exporter")
	// 	os.Exit(1)
	// }

	exporter, err := jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(s.cfg.JaegerExporterURL)))
	if err != nil {
		level.Error(s.Logger).Log("err", err, "msg", "Could not create jaeger exporter")
		os.Exit(1)
	}

	// For the demonstration, use sdktrace.AlwaysSample sampler to sample all traces.
	// In a production application, use sdktrace.ProbabilitySampler with a desired probability.
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(s.cfg.ServiceName),
			attribute.String("environment", s.cfg.DeploymentEnvironment),
		)),
	)
	otel.SetTracerProvider(tp)
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
