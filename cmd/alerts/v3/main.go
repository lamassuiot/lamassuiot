package main

import (
	"context"
	"fmt"

	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/messaging"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/routes"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
	"github.com/lamassuiot/lamassuiot/pkg/v3/storage"
	"github.com/lamassuiot/lamassuiot/pkg/v3/storage/postgres"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

var (
	version   string = "v0"    // api version
	sha1ver   string = "-"     // sha1 revision used to build the program
	buildTime string = "devTS" // when the executable was built
)

func main() {
	log.SetFormatter(helpers.LogFormatter)
	log.Infof("starting api: version=%s buildTime=%s sha1ver=%s", version, buildTime, sha1ver)

	conf, err := config.LoadConfig[config.AlertsConfig]()
	if err != nil {
		log.Fatal(err)
	}

	globalLogLevel, err := log.ParseLevel(string(conf.Logs.Level))
	if err != nil {
		log.Warn("unknown log level. defaulting to 'info' log level")
		globalLogLevel = log.InfoLevel
	}
	log.SetLevel(globalLogLevel)

	log.Infof("global log level set to '%s'", globalLogLevel)

	confBytes, err := yaml.Marshal(conf)
	if err != nil {
		log.Fatalf("could not dump yaml config: %s", err)
	}
	log.Debugf("===================================================")
	log.Debugf("%s", confBytes)
	log.Debugf("===================================================")

	lSvc := helpers.ConfigureLogger(globalLogLevel, conf.Logs.SubsystemLogging.Service, "Service")
	lHttp := helpers.ConfigureLogger(globalLogLevel, conf.Logs.SubsystemLogging.HttpTransport, "HTTP Server")
	lMessage := helpers.ConfigureLogger(globalLogLevel, conf.Logs.SubsystemLogging.MessagingEngine, "Messaging")
	lStorage := helpers.ConfigureLogger(globalLogLevel, conf.Logs.SubsystemLogging.StorageEngine, "Storage")

	subStorage, eventStore, err := createStorageInstance(lStorage, conf.Storage)
	if err != nil {
		log.Fatal(err)
	}

	svc := services.NewAlertsService(services.AlertsServiceBuilder{
		Logger:           lSvc,
		SubsStorage:      subStorage,
		EventStorage:     eventStore,
		SmtpServerConfig: conf.SMTPConfig,
	})

	if conf.AMQPConnection.Enabled {
		log.Infof("AMQP Connection enabled")
		amqpConnection, err := messaging.SetupAMQPConnection(lMessage, conf.AMQPConnection)
		if err != nil {
			log.Fatal(err)
		}

		amqpConnection.SetupAMQPEventSubscriber("alerts-v2", []string{"#"})

		onMessage := amqpConnection.Msgs
		go func() {
			lMessage.Info("ready to receive messages")
			for {
				select {
				case msg := <-onMessage:
					lMessage.Trace("new incoming message")
					event, err := messaging.ParseCloudEvent(msg.Body)
					if err != nil {
						lMessage.Errorf("could not decode message into cloud event: %s", err)
						continue
					}
					svc.HandleEvent(context.Background(), &services.HandleEventInput{
						Event: *event,
					})
				}
			}
		}()
	}

	// svc.Subscribe(context.Background(), &services.SubscribeInput{
	// 	UserID:     "hsaiz",
	// 	EventType:  models.EventSignCertificate,
	// 	Conditions: []models.SubscriptionCondition{},
	// 	Channel: models.Channel{
	// 		Type: models.ChannelTypeEmail,
	// 		Config: models.EmailConfig{
	// 			Email: "hsaiz@ikerlan.es",
	// 		},
	// 	},
	// })

	router := routes.NewAlertsHTTPLayer(lHttp, svc)
	routes.RunHttpRouter(lHttp, router, conf.Server, models.APIServiceInfo{
		Version:   version,
		BuildSHA:  sha1ver,
		BuildTime: buildTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	forever := make(chan struct{})
	<-forever
}

func createStorageInstance(logger *log.Entry, conf config.PluggableStorageEngine) (storage.SubscriptionsRepository, storage.EventRepository, error) {
	switch conf.Provider {
	case config.Postgres:
		psqlCli, err := postgres.CreatePostgresDBConnection(logger, conf.Postgres, "alerts")
		if err != nil {
			log.Fatalf("could not create postgres client: %s", err)
		}

		subStore, err := postgres.NewSubscriptionsPostgresRepository(psqlCli)
		if err != nil {
			log.Fatalf("could not initialize postgres Alerts client: %s", err)
		}

		eventsStore, err := postgres.NewEventsPostgresRepository(psqlCli)
		if err != nil {
			log.Fatalf("could not initialize postgres Alerts client: %s", err)
		}

		return subStore, eventsStore, nil
	}

	return nil, nil, fmt.Errorf("no storage engine")
}
