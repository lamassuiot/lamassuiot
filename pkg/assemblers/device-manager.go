package assemblers

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/eventbus"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/middlewares/eventpub"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/routes"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services/handlers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage/builder"
	"github.com/sirupsen/logrus"
)

func AssembleDeviceManagerServiceWithHTTPServer(conf config.DeviceManagerConfig, caService services.CAService, serviceInfo models.APIServiceInfo) (*services.DeviceManagerService, int, error) {
	service, err := AssembleDeviceManagerService(conf, caService)
	if err != nil {
		return nil, -1, fmt.Errorf("could not assemble Device Manager Service. Exiting: %s", err)
	}

	lHttp := helpers.SetupLogger(conf.Server.LogLevel, "Device Manager", "HTTP Server")

	httpEngine := routes.NewGinEngine(lHttp)
	httpGrp := httpEngine.Group("/")
	routes.NewDeviceManagerHTTPLayer(httpGrp, *service)
	port, err := routes.RunHttpRouter(lHttp, httpEngine, conf.Server, serviceInfo)
	if err != nil {
		return nil, -1, fmt.Errorf("could not run Device Manager http server: %s", err)
	}

	return service, port, nil
}

func AssembleDeviceManagerService(conf config.DeviceManagerConfig, caService services.CAService) (*services.DeviceManagerService, error) {
	serviceID := "device-manager"

	lSvc := helpers.SetupLogger(conf.Logs.Level, "Device Manager", "Service")
	lStorage := helpers.SetupLogger(conf.Storage.LogLevel, "Device Manager", "Storage")
	lStorageEvents := helpers.SetupLogger(conf.Storage.LogLevel, "Device Manager", "Storage - Events")

	devStorage, err := createDevicesStorageInstance(lStorage, conf.Storage)
	if err != nil {
		return nil, fmt.Errorf("could not create device storage: %s", err)
	}

	eventStorage, err := createDeviceEventsStorageInstance(lStorageEvents, conf.Storage)
	if err != nil {
		return nil, fmt.Errorf("could not create device events storage: %s", err)
	}

	svc := services.NewDeviceManagerService(services.DeviceManagerBuilder{
		Logger:         lSvc,
		DevicesStorage: devStorage,
		DeviceEvents:   eventStorage,
		CAClient:       caService,
	})

	deviceSvc := svc.(*services.DeviceManagerServiceBackend)

	if conf.PublisherEventBus.Enabled {
		lMessaging := helpers.SetupLogger(conf.PublisherEventBus.LogLevel, "Device Manager", "Event Bus")
		lMessaging.Infof("Publisher Event Bus is enabled")
		pub, err := eventbus.NewEventBusPublisher(conf.PublisherEventBus, serviceID, lMessaging)
		if err != nil {
			return nil, fmt.Errorf("could not create Event Bus publisher: %s", err)
		}

		svc = eventpub.NewDeviceEventPublisher(&eventpub.CloudEventMiddlewarePublisher{
			Publisher: pub,
			ServiceID: serviceID,
			Logger:    lMessaging,
		})(svc)

		deviceSvc.SetService(svc)
	}

	if conf.SubscriberEventBus.Enabled {

		lMessaging := helpers.SetupLogger(conf.SubscriberEventBus.LogLevel, "Device Manager", "Event Bus")
		lMessaging.Infof("Subscriber Event Bus is enabled")

		handler := handlers.NewDeviceEventHandler(lMessaging, svc)
		subHandler, err := eventbus.NewEventBusSubscriptionHandler(conf.SubscriberEventBus, serviceID, lMessaging, *handler, fmt.Sprintf("certificate.#-%s", serviceID), "certificate.#")
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

func createDevicesStorageInstance(logger *logrus.Entry, conf config.PluggableStorageEngine) (storage.DeviceManagerRepo, error) {
	storage, err := builder.BuildStorageEngine(logger, conf)
	if err != nil {
		return nil, fmt.Errorf("could not create storage engine: %s", err)
	}
	deviceStorage, err := storage.GetDeviceStorage()
	if err != nil {
		return nil, fmt.Errorf("could not get device storage: %s", err)
	}
	return deviceStorage, nil
}

func createDeviceEventsStorageInstance(logger *logrus.Entry, conf config.PluggableStorageEngine) (storage.DeviceEventsRepo, error) {
	storage, err := builder.BuildStorageEngine(logger, conf)
	if err != nil {
		return nil, fmt.Errorf("could not create storage engine: %s", err)
	}

	eventStorage, err := storage.GetDeviceEventsStorage()
	if err != nil {
		return nil, fmt.Errorf("could not get device storage: %s", err)
	}

	return eventStorage, nil
}
