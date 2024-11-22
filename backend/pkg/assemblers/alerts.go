package assemblers

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/v3/backend/pkg/config"
	"github.com/lamassuiot/lamassuiot/v3/backend/pkg/eventbus"
	"github.com/lamassuiot/lamassuiot/v3/backend/pkg/routes"
	"github.com/lamassuiot/lamassuiot/v3/backend/pkg/services"
	"github.com/lamassuiot/lamassuiot/v3/backend/pkg/services/handlers"
	"github.com/lamassuiot/lamassuiot/v3/backend/pkg/storage/builder"
	cconfig "github.com/lamassuiot/lamassuiot/v3/core/pkg/config"
	ceventbus "github.com/lamassuiot/lamassuiot/v3/core/pkg/engines/eventbus"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/models"
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
		Logger:           lSvc,
		SubsStorage:      subStorage,
		EventStorage:     eventStore,
		SmtpServerConfig: conf.SMTPConfig,
	})

	if conf.SubscriberEventBus.Enabled {
		log.Infof("Event Bus is enabled")

		subscriber, err := eventbus.NewEventBusSubscriber(conf.SubscriberEventBus, "alerts", lMessaging)
		if err != nil {
			lMessaging.Errorf("could not generate Event Bus Subscriber: %s", err)
			return nil, err
		}

		eventHandlers := handlers.NewAlertsEventHandler(lMessaging, svc)
		subHandler, err := ceventbus.NewEventBusMessageHandler("Alerts-DEFAULT", "#", subscriber, lMessaging, *eventHandlers)
		if err != nil {
			return nil, fmt.Errorf("could not create Event Bus Subscription Handler: %s", err)
		}

		err = subHandler.RunAsync()
		if err != nil {
			lMessaging.Errorf("could not run Event Bus Subscription Handler: %s", err)
			return nil, err
		}
	}

	return &svc, nil
}

func createAlertsStorageInstance(logger *log.Entry, conf cconfig.PluggableStorageEngine) (storage.SubscriptionsRepository, storage.EventRepository, error) {
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
