package assemblers

import (
	"context"
	"fmt"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/messaging"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/routes"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage/postgres"
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
	lMessaging := helpers.ConfigureLogger(conf.EventBus.LogLevel, "Event Bus")
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

	if conf.EventBus.Enabled {
		log.Infof("Event Bus is enabled")
		eventBus, err := messaging.NewMessagingEngine(lMessaging, conf.EventBus, "alerts")
		if err != nil {
			return nil, fmt.Errorf("could not setup event bus: %s", err)
		}

		panicHandler := func(eventType string, msg *message.Message) {
			if err := recover(); err != nil {
				serializedMsg := "<message is nil>"
				if msg != nil && msg.Payload != nil {
					serializedMsg = string(msg.Payload)
				}
				lMessaging.Errorf("prevented panic while handling %s event. Faulty message: %s", eventType, serializedMsg)
			}
		}

		subscribeAndHandle := func(eventType string, messageHandler func(msg *message.Message)) error {
			subscriber, err := eventBus.Subscriber.Subscribe(context.Background(), eventType)
			if err != nil {
				return err
			}

			panicSafeMessageHandler := func(msg *message.Message) {
				defer panicHandler(eventType, msg)
				messageHandler(msg)
			}

			for {
				select {
				case message := <-subscriber:
					panicSafeMessageHandler(message)
					message.Ack()
				}
			}
		}

		lamassuEventHandler := func(msg *message.Message) {
			event, err := messaging.ParseCloudEvent(msg.Payload)
			if err != nil {
				lMessaging.Errorf("Something went wrong while processing cloud event: %s", err)
			}

			svc.HandleEvent(context.Background(), &services.HandleEventInput{
				Event: *event,
			})
		}

		go subscribeAndHandle("#", lamassuEventHandler)
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
