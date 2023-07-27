package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/utils"
	log "github.com/sirupsen/logrus"

	amqptransport "github.com/go-kit/kit/transport/amqp"

	"github.com/kelseyhightower/envconfig"
	"github.com/streadway/amqp"
	"golang.org/x/exp/slices"
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
	ServiceName            string `required:"true" split_words:"true"`
	DebugMode              bool   `required:"true" split_words:"true"`
	Port                   string `required:"true" split_words:"true"`
	Protocol               string `required:"true" split_words:"true"`
	CertFile               string `split_words:"true"`
	KeyFile                string `split_words:"true"`
	MutualTLSEnabled       bool   `split_words:"true"`
	MutualTLSClientCA      string `split_words:"true"`
	AmqpServerHost         string `required:"true" split_words:"true"`
	AmqpServerEnableTLS    bool   `required:"true" split_words:"true"`
	AmqpServerPort         string `required:"true" split_words:"true"`
	AmqpServerCACert       string `split_words:"true"`
	AmqpServerUseBasicAuth bool   `required:"true" split_words:"true"`
	AmqpServerUsername     string `split_words:"true"`
	AmqpServerPassword     string `split_words:"true"`
}

type AmqpPublishMessage struct {
	Exchange  string
	Key       string
	Mandatory bool
	Immediate bool
	Msg       amqp.Publishing
}

type amqpConsumerConfig struct {
	Subscriber  *amqptransport.Subscriber
	RoutingKeys []string
}

type Server struct {
	cfg                 *BaseConfiguration
	mux                 *http.ServeMux
	amqpConn            *amqp.Connection
	amqpChanNotifyClose chan *amqp.Error
	amqpConsumers       map[string]amqpConsumerConfig //map queuName to amqptransport.Subscriber and routing key
	AmqpPublisher       chan AmqpPublishMessage
}

func NewServer(config Configuration) *Server {
	log.SetFormatter(&log.TextFormatter{
		ForceColors:   true,
		FullTimestamp: true,
		SortingFunc: func(s []string) {
			methodIdx := slices.IndexFunc(s, func(item string) bool {
				return item == "method"
			})

			if methodIdx != -1 {
				s = utils.SliceMove(s, methodIdx, 0)
			}
		},
	})

	err := envconfig.Process("", config.GetConfiguration())
	if err != nil {
		log.Fatal("Could not process configuration: ", err)
		os.Exit(1)
	}

	baseConfig := config.GetBaseConfiguration()

	if baseConfig.DebugMode {
		log.SetLevel(log.TraceLevel)
		log.Trace("Starting in debug mode")
	}

	mux := http.NewServeMux()

	//http.HandleFunc("/", httpTraceLogHandler)
	http.Handle("/info", accessControl(infoHandler()))

	s := Server{
		cfg:           baseConfig,
		mux:           mux,
		amqpConsumers: map[string]amqpConsumerConfig{},
		AmqpPublisher: make(chan AmqpPublishMessage, 100),
	}

	return &s
}

func (s *Server) AddAmqpConsumer(queuName string, routingKeys []string, subscriber *amqptransport.Subscriber) {
	s.amqpConsumers[queuName] = amqpConsumerConfig{
		Subscriber:  subscriber,
		RoutingKeys: routingKeys,
	}
}

func (s *Server) AddHttpHandler(path string, handler http.Handler) {
	WithLogging := func(h http.Handler) http.Handler {
		logFn := func(rw http.ResponseWriter, r *http.Request) {
			start := time.Now()

			uri := r.RequestURI
			method := r.Method
			h.ServeHTTP(rw, r) // serve the original request

			duration := time.Since(start)

			// log request details
			log.Debug(log.WithFields(log.Fields{
				"uri":      uri,
				"method":   method,
				"duration": duration,
			}))
		}
		return http.HandlerFunc(logFn)
	}

	http.Handle(path, WithLogging(accessControl(handler)))
}

func (s *Server) AddHttpFuncHandler(path string, handler func(http.ResponseWriter, *http.Request)) {
	http.HandleFunc(path, handler)
}

func (s *Server) Run() {
	go func() {
		err := s.buildAMQPConnection()
		if err != nil {
			log.Fatal(err)
		}

		go func() {
			for {
				select { //check connection
				case err = <-s.amqpChanNotifyClose:
					//work with error
					log.Error("Disconnected from AMQP: ", err)
					for {
						err = s.buildAMQPConnection()
						if err != nil {
							log.Error("Failed to reconnect. Sleeping for 5 secodns: ", err)
							time.Sleep(5 * time.Second)
						} else {
							break
						}
					}
					log.Info("AMQP reconnection success: ", err)
				}
			}
		}()
		// defer amqpConn.Close()

		amqpChannel, err := s.amqpConn.Channel()
		if err != nil {
			log.Fatal("Failed to create AMQP channel: ", err)
		}
		// defer amqpChannel.Close()

		amqpChannel.ExchangeDeclare(
			"lamassu", // name
			"topic",   // type
			true,      // durable
			false,     // auto-deleted
			false,     // internal
			false,     // no-wait
			nil,       // arguments
		)

		for queueName, consumerConfig := range s.amqpConsumers {
			consumerQueue, err := amqpChannel.QueueDeclare(queueName, true, false, false, false, nil)
			if err != nil {
				log.Fatal(fmt.Sprintf("Failed to create AMQP %s queue: ", queueName), err)
			}

			for _, routingKey := range consumerConfig.RoutingKeys {
				err = amqpChannel.QueueBind(
					consumerQueue.Name, // queue name
					routingKey,         // routing key
					"lamassu",          // exchange
					false,
					nil,
				)
				if err != nil {
					log.Fatal(fmt.Sprintf("Failed to bind AMQP [%s] queue with routing key [%s]: ", queueName, routingKey), err)
				}
			}

			msgDelivery, err := amqpChannel.Consume(consumerQueue.Name, fmt.Sprintf("%s-consumer-%s", s.cfg.ServiceName, queueName), true, false, false, false, nil)
			if err != nil {
				log.Fatal(fmt.Sprintf("Failed to consume AMQP %s queue: ", queueName), err)
			}

			msgHandler := consumerConfig.Subscriber.ServeDelivery(amqpChannel)

			go func() {
				for {
					select {
					case msg := <-msgDelivery:
						msgHandler(&msg)
					}
				}
			}()

			log.Info(fmt.Sprintf("Waiting for AMQP messaged in queue %s", queueName))
		}

		go func() {
			for {
				select {
				case amqpMessage := <-s.AmqpPublisher:
					amqpErr := amqpChannel.Publish(amqpMessage.Exchange, amqpMessage.Key, amqpMessage.Mandatory, amqpMessage.Immediate, amqpMessage.Msg)
					if amqpErr != nil {
						log.Error("Error while publishing to AMQP queue: ", amqpErr)
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
						log.Fatal("Could not read client CA file: ", err)
					}

					if !mTlsCertPool.AppendCertsFromPEM(caCert) {
						log.Fatal("Could not append client CA to cert pool")
					}

					tlsConfig := &tls.Config{
						// ClientCAs:  mTlsCertPool,
						ClientAuth: tls.RequireAnyClientCert,
					}

					http := &http.Server{
						Addr:      ":" + s.cfg.Port,
						TLSConfig: tlsConfig,
					}

					log.Info("Listening on port " + s.cfg.Port + " using HTTPS and mTLS")
					err = http.ListenAndServeTLS(s.cfg.CertFile, s.cfg.KeyFile)
					if err != nil {
						log.Fatal("Could not start HTTPS server with mTLS: ", err)
					}
				} else {
					log.Info("Listening on port " + s.cfg.Port + " using HTTPS")
					err = http.ListenAndServeTLS(":"+s.cfg.Port, s.cfg.CertFile, s.cfg.KeyFile, nil)
					if err != nil {
						log.Fatal("Could not start HTTPS server: ", err)
					}
				}
			} else if strings.ToLower(s.cfg.Protocol) == "http" {
				log.Info("Listening on port " + s.cfg.Port + " using HTTP")
				if err != nil {
					err = http.ListenAndServe(":"+s.cfg.Port, nil)
				}
			} else {
				log.Fatal("Unknown protocol")
			}
		}()

	}()
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

func (s *Server) buildAMQPConnection() error {
	userPassUrlPrefix := ""
	var amqpConn *amqp.Connection
	if s.cfg.AmqpServerUseBasicAuth {
		userPassUrlPrefix = fmt.Sprintf("%s:%s@", s.cfg.AmqpServerUsername, s.cfg.AmqpServerPassword)
	}

	if s.cfg.AmqpServerEnableTLS {
		amq_cfg := tls.Config{}
		amq_cfg.RootCAs = x509.NewCertPool()

		amqpCA, err := ioutil.ReadFile(s.cfg.AmqpServerCACert)
		if err != nil {
			log.Error("Could not read AMQP CA certificate: ", err)
		}

		amq_cfg.RootCAs.AppendCertsFromPEM(amqpCA)
		cert, err := tls.LoadX509KeyPair(s.cfg.CertFile, s.cfg.KeyFile)

		if err != nil {
			log.Error("Could not load AMQP TLS certificate: ", err)
		}

		amq_cfg.Certificates = append(amq_cfg.Certificates, cert)

		amqpURI := fmt.Sprintf("amqps://%s%s:%s", userPassUrlPrefix, s.cfg.AmqpServerHost, s.cfg.AmqpServerPort)
		log.Debug("connecting to ", amqpURI)
		amqpConn, err = amqp.DialTLS(amqpURI, &amq_cfg)

		if err != nil {
			log.Error("Failed to connect to AMQP with TLS: ", err)
			return err
		}
		s.amqpConn = amqpConn
	} else {
		amqpConn, err := amqp.Dial(fmt.Sprintf("amqp://%s%s:%s", userPassUrlPrefix, s.cfg.AmqpServerHost, s.cfg.AmqpServerPort))
		if err != nil {
			log.Error("Failed to connect to AMQP: ", err)
			return err
		}
		s.amqpConn = amqpConn
	}

	s.amqpChanNotifyClose = s.amqpConn.NotifyClose(make(chan *amqp.Error)) //error channel
	return nil
}

func httpTraceLogHandler(w http.ResponseWriter, r *http.Request) {
	reqDump, err := httputil.DumpRequest(r, true)
	if err != nil {
		log.Fatal(err)
	}

	log.Trace(string(reqDump))
}
