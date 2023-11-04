package lamassu

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
)

func AssembleAlertsServiceWithHTTPServer(conf config.AlertsConfig, serviceInfo models.APIServiceInfo) (*services.AlertsService, int, error) {
	service, err := AssembleAlertsService(conf)
	if err != nil {
		return nil, -1, fmt.Errorf("could not assemble Alerts Service. Exiting: %s", err)
	}

	lHttp := helpers.ConfigureLogger(conf.Server.LogLevel, "HTTP Server")

	httpEngine := routes.NewGinEngine(lHttp)
	httpGrp := httpEngine.Group("/")
	routes.NewAlertsHTTPLayer(httpGrp, *service)
	port, err := routes.RunHttpRouter(lHttp, httpEngine, conf.Server, serviceInfo)
	if err != nil {
		return nil, -1, fmt.Errorf("could not run Alerts http server: %s", err)
	}

	return service, port, nil
}

func AssembleAlertsService(conf config.AlertsConfig) (*services.AlertsService, error) {
	lSvc := helpers.ConfigureLogger(conf.Logs.Level, "Service")
	lMessage := helpers.ConfigureLogger(conf.AMQPConnection.LogLevel, "Messaging")
	lStorage := helpers.ConfigureLogger(conf.Storage.LogLevel, "Storage")

	subStorage, eventStore, err := createAlertsStorageInstance(lStorage, conf.Storage)
	if err != nil {
		return nil, fmt.Errorf("could not create alerts storage instance: %s", err)
	}

	svc := services.NewAlertsService(services.AlertsServiceBuilder{
		Logger:       lSvc,
		SubsStorage:  subStorage,
		EventStorage: eventStore,
	})

	if conf.AMQPConnection.Enabled {
		log.Infof("AMQP Connection enabled")
		amqpConnection, err := messaging.SetupAMQPConnection(lMessage, conf.AMQPConnection)
		if err != nil {
			return nil, fmt.Errorf("could not setup amqp connection: %s", err)
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

	return &svc, nil
}

func createAlertsStorageInstance(logger *log.Entry, conf config.PluggableStorageEngine) (storage.SubscriptionsRepository, storage.EventRepository, error) {
	switch conf.Provider {
	case config.Postgres:
		psqlCli, err := postgres.CreatePostgresDBConnection(logger, conf.Postgres, "alerts")
		if err != nil {
			return nil, nil, fmt.Errorf("could not create postgres client: %s", err)
		}

		subStore, err := postgres.NewSubscriptionsPostgresRepository(psqlCli)
		if err != nil {
			return nil, nil, fmt.Errorf("could not initialize postgres Alerts client: %s", err)
		}

		eventsStore, err := postgres.NewEventsPostgresRepository(psqlCli)
		if err != nil {
			return nil, nil, fmt.Errorf("could not initialize postgres Alerts client: %s", err)
		}

		return subStore, eventsStore, nil
	}

	return nil, nil, fmt.Errorf("no storage engine")
}
