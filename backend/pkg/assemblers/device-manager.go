package assemblers

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/eventbus"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/middlewares/eventpub"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes"
	lservices "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/services/handlers"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/storage/builder"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	ceventbus "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/eventbus"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/eventpublisher"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
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

	devStorage, err := createDevicesStorageInstance(lStorage, conf.Storage)
	if err != nil {
		return nil, fmt.Errorf("could not create device storage: %s", err)
	}

	svc := lservices.NewDeviceManagerService(lservices.DeviceManagerBuilder{
		Logger:         lSvc,
		DevicesStorage: devStorage,
		CAClient:       caService,
	})

	deviceSvc := svc.(*lservices.DeviceManagerServiceBackend)

	lMessaging := helpers.SetupLogger(conf.PublisherEventBus.LogLevel, "Device Manager", "Event Bus")
	lMessaging.Infof("Publisher Event Bus is enabled")

	if conf.PublisherEventBus.Enabled {
		pub, err := eventbus.NewEventBusPublisher(conf.PublisherEventBus, serviceID, lMessaging)
		if err != nil {
			return nil, fmt.Errorf("could not create Event Bus publisher: %s", err)
		}

		svc = eventpub.NewDeviceEventPublisher(&eventpublisher.CloudEventPublisher{
			Publisher: pub,
			ServiceID: serviceID,
			Logger:    lMessaging,
		})(svc)

		//this utilizes the middlewares from within the DeviceManager service (if svc.service.func is used instead of regular svc.func)
		deviceSvc.SetService(svc)
	}

	if conf.SubscriberEventBus.Enabled {
		if !conf.SubscriberDLQEventBus.Enabled {
			lMessaging.Fatalf("Subscriber Event Bus is enabled but DLQ is not enabled. This is not supported. Exiting")
		} else {
			dlqPublisher, err := eventbus.NewEventBusPublisher(conf.SubscriberDLQEventBus, serviceID, lMessaging)
			if err != nil {
				return nil, fmt.Errorf("could not create Event Bus publisher: %s", err)
			}

			lMessaging := helpers.SetupLogger(conf.SubscriberEventBus.LogLevel, "Device Manager", "Event Bus")
			lMessaging.Infof("Subscriber Event Bus is enabled")

			subscriber, err := eventbus.NewEventBusSubscriber(conf.SubscriberEventBus, serviceID, lMessaging)
			if err != nil {
				lMessaging.Errorf("could not generate Event Bus Subscriber: %s", err)
				return nil, err
			}

			eventHandlers := handlers.NewDeviceEventHandler(lMessaging, svc)
			subHandler, err := ceventbus.NewEventBusMessageHandler("DeviceManger-DEFAULT", []string{"certificate.#"}, dlqPublisher, subscriber, lMessaging, *eventHandlers)
			if err != nil {
				return nil, fmt.Errorf("could not create Event Bus Subscription Handler: %s", err)
			}

			if err := subHandler.RunAsync(); err != nil {
				lMessaging.Errorf("could not run Event Bus Subscription Handler: %s", err)
				return nil, err
			}
		}
	}

	return &svc, nil
}

func createDevicesStorageInstance(logger *logrus.Entry, conf cconfig.PluggableStorageEngine) (storage.DeviceManagerRepo, error) {
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
