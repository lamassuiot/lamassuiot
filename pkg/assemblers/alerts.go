package assemblers

import (
	"context"
	"fmt"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/eventbus"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/routes"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services/handlers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage/builder"
	log "github.com/sirupsen/logrus"
)

func AssembleAlertsServiceWithHTTPServer(conf config.AlertsConfig, serviceInfo models.APIServiceInfo) (*services.AlertsService, int, error) {
	service, err := AssembleAlertsService(conf)
	if err != nil {
		return nil, -1, fmt.Errorf("could not assemble Alerts Service. Exiting: %s", err)
	}

	lHttp := helpers.SetupLogger(conf.Server.LogLevel, "Alerts", "HTTP Server")

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
	lSvc := helpers.SetupLogger(conf.Logs.Level, "Alerts", "Service")
	lMessaging := helpers.SetupLogger(conf.SubscriberEventBus.LogLevel, "Alerts", "Event Bus")
	lStorage := helpers.SetupLogger(conf.Storage.LogLevel, "Alerts", "Storage")

	subStorage, eventStore, err := createAlertsStorageInstance(lStorage, conf.Storage)
	if err != nil {
		return nil, fmt.Errorf("could not create alerts storage instance: %s", err)
	}

	svc := services.NewAlertsService(services.AlertsServiceBuilder{
		Logger:       lSvc,
		SubsStorage:  subStorage,
		EventStorage: eventStore,
	})

	if conf.SubscriberEventBus.Enabled {
		log.Infof("Event Bus is enabled")
		eventBusRouter, err := eventbus.NewEventBusRouter(conf.SubscriberEventBus, "alerts", lMessaging)
		if err != nil {
			return nil, fmt.Errorf("could not setup event bus: %s", err)
		}

		sub, err := eventbus.NewEventBusSubscriber(conf.SubscriberEventBus, "alerts", lMessaging)
		if err != nil {
			lMessaging.Errorf("could not generate Event Bus Subscriber: %s", err)
			return nil, err
		}

		handler := handlers.NewAlertsEventHandler(lMessaging, svc)
		eventBusRouter.AddNoPublisherHandler("#-alerts", "#", sub, handler.HandleEvent)
		go eventBusRouter.Run(context.Background())
	}

	return &svc, nil
}

func GetAlertsEventHandler(lMessaging *log.Entry, svc services.AlertsService) func(*message.Message) error {
	return func(m *message.Message) error {
		event, err := eventbus.ParseCloudEvent(m.Payload)
		if err != nil {
			lMessaging.Errorf("Something went wrong while processing cloud event: %s", err)
		}

		err = svc.HandleEvent(context.Background(), &services.HandleEventInput{
			Event: *event,
		})
		if err != nil {
			lMessaging.Errorf("Something went wrong while handling event: %s", err)
			return err
		}

		return nil
	}
}

func createAlertsStorageInstance(logger *log.Entry, conf config.PluggableStorageEngine) (storage.SubscriptionsRepository, storage.EventRepository, error) {
	engine, err := builder.BuildStorageEngine(logger, conf)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create storage engine: %s", err)
	}

	subStore, err := engine.GetSubscriptionsStorage()
	if err != nil {
		return nil, nil, fmt.Errorf("could not get subscriptions storage: %s", err)
	}

	eventsStore, err := engine.GetEnventsStorage()
	if err != nil {
		return nil, nil, fmt.Errorf("could not get event storage: %s", err)
	}

	return subStore, eventsStore, nil
}
