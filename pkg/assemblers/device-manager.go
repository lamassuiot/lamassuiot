package assemblers

import (
	"context"
	"fmt"
	"slices"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/eventbus"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/middlewares/eventpub"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/routes"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage/couchdb"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage/postgres"
	"github.com/sirupsen/logrus"
)

func AssembleDeviceManagerServiceWithHTTPServer(conf config.DeviceManagerConfig, caService services.CAService, serviceInfo models.APIServiceInfo) (*services.DeviceManagerService, int, error) {
	service, err := AssembleDeviceManagerService(conf, caService)
	if err != nil {
		return nil, -1, fmt.Errorf("could not assemble Device Manager Service. Exiting: %s", err)
	}

	lHttp := helpers.ConfigureLogger(conf.Server.LogLevel, "Device Manager", "HTTP Server")

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

	lSvc := helpers.ConfigureLogger(conf.Logs.Level, "Device Manager", "Service")
	lStorage := helpers.ConfigureLogger(conf.Storage.LogLevel, "Device Manager", "Storage")

	devStorage, err := createDevicesStorageInstance(lStorage, conf.Storage)
	if err != nil {
		return nil, fmt.Errorf("could not create device storage: %s", err)
	}

	svc := services.NewDeviceManagerService(services.DeviceManagerBuilder{
		Logger:         lSvc,
		DevicesStorage: devStorage,
		CAClient:       caService,
	})

	deviceSvc := svc.(*services.DeviceManagerServiceBackend)

	if conf.PublisherEventBus.Enabled {
		lMessaging := helpers.ConfigureLogger(conf.PublisherEventBus.LogLevel, "Device Manager", "Event Bus")
		lMessaging.Infof("Publisher Event Bus is enabled")
		pub, err := eventbus.NewEventBusPublisher(conf.PublisherEventBus, serviceID, lMessaging)
		if err != nil {
			return nil, fmt.Errorf("could not create Event Bus publisher: %s", err)
		}

		svc = eventpub.NewDeviceEventPublisher(eventpub.CloudEventMiddlewarePublisher{
			Publisher: pub,
			ServiceID: serviceID,
			Logger:    lMessaging,
		})(svc)

		deviceSvc.SetService(svc)
	}

	if conf.SubscriberEventBus.Enabled {
		lMessaging := helpers.ConfigureLogger(conf.SubscriberEventBus.LogLevel, "Device Manager", "Event Bus")
		lMessaging.Infof("Subscriber Event Bus is enabled")

		eventBusRouter, err := eventbus.NewEventBusRouter(conf.SubscriberEventBus, serviceID, lMessaging)
		if err != nil {
			return nil, fmt.Errorf("could not create Event Bus Router: %s", err)
		}

		sub, err := eventbus.NewEventBusSubscriber(conf.SubscriberEventBus, serviceID, lMessaging)
		if err != nil {
			return nil, fmt.Errorf("could not create Event Bus subscriber: %s", err)
		}

		eventBusRouter.AddNoPublisherHandler(fmt.Sprintf("certificate.#-%s", serviceID), "certificate.#", sub, GetDeviceManagerEventHandler(lMessaging, svc))

		go eventBusRouter.Run(context.Background())
	}

	return &svc, nil
}

func GetDeviceManagerEventHandler(lMessaging *logrus.Entry, svc services.DeviceManagerService) func(*message.Message) error {
	return func(m *message.Message) error {
		event, err := eventbus.ParseCloudEvent(m.Payload)
		if err != nil {
			err = fmt.Errorf("something went wrong while processing cloud event: %s", err)
			lMessaging.Error(err)
			return err
		}

		switch event.Type() {
		case string(models.EventUpdateCertificateMetadataKey):
			updateCertMetaHandler(event, svc, lMessaging)

		case string(models.EventUpdateCertificateStatusKey):
			updateCertStatusHandler(event, svc, lMessaging)
		}

		return nil
	}
}

func updateCertStatusHandler(event *event.Event, svc services.DeviceManagerService, lMessaging *logrus.Entry) error {
	cert, err := eventbus.GetEventBody[models.UpdateModel[models.Certificate]](event)
	if err != nil {
		err = fmt.Errorf("could not decode cloud event: %s", err)
		lMessaging.Error(err)
		return err
	}

	deviceID := cert.Updated.Certificate.Subject.CommonName
	dev, err := svc.GetDeviceByID(services.GetDeviceByIDInput{
		ID: deviceID,
	})
	if err != nil {
		err = fmt.Errorf("could not get device %s: %s", deviceID, err)
		lMessaging.Error(err)
		return err
	}

	var attachedBy models.CAAttachedToDevice
	hasKey, err := helpers.GetMetadataToStruct(cert.Updated.Metadata, models.CAAttachedToDeviceKey, &attachedBy)
	if err != nil {
		err = fmt.Errorf("could not decode metadata with key %s: %s", models.CAAttachedToDeviceKey, err)
		lMessaging.Error(err)
		return err
	}

	if !hasKey {
		lMessaging.Tracef("skipping event %s, Certificate doesn't have %s key", event.Type(), models.CAAttachedToDeviceKey)
		return nil
	}

	if dev.IdentitySlot.Secrets[dev.IdentitySlot.ActiveVersion] != cert.Updated.SerialNumber {
		//event is not for the active certificate. Skip
		return nil
	}

	updated := false
	if cert.Updated.Status == models.StatusExpired {
		updated = true
		dev.IdentitySlot.Status = models.SlotExpired
	}
	if cert.Updated.Status == models.StatusRevoked {
		updated = true
		dev.IdentitySlot.Status = models.SlotRevoke
	}

	if updated {
		_, err = svc.UpdateDeviceIdentitySlot(services.UpdateDeviceIdentitySlotInput{
			ID:   deviceID,
			Slot: *dev.IdentitySlot,
		})
		if err != nil {
			err = fmt.Errorf("could not update ID slot to preventive for device %s: %s", deviceID, err)
			lMessaging.Error(err)
			return err
		}
	}
	return nil
}

func updateCertMetaHandler(event *event.Event, svc services.DeviceManagerService, lMessaging *logrus.Entry) error {
	certUpdate, err := eventbus.GetEventBody[models.UpdateModel[models.Certificate]](event)
	if err != nil {
		err = fmt.Errorf("could not decode cloud event: %s", err)
		lMessaging.Error(err)
		return err
	}

	deviceID := certUpdate.Updated.Subject.CommonName
	dev, err := svc.GetDeviceByID(services.GetDeviceByIDInput{
		ID: deviceID,
	})
	if err != nil {
		err = fmt.Errorf("could not get device %s: %s", deviceID, err)
		lMessaging.Error(err)
		return err
	}

	if dev.IdentitySlot != nil && dev.IdentitySlot.Secrets[dev.IdentitySlot.ActiveVersion] != certUpdate.Updated.SerialNumber {
		//event is not for the active certificate. Skip
		return nil
	}

	checkIfTriggered := func(crt models.Certificate, key string) bool {
		var deltas models.CAMetadataMonitoringExpirationDeltas
		hasKey, err := helpers.GetMetadataToStruct(crt.Metadata, models.CAMetadataMonitoringExpirationDeltasKey, &deltas)
		if err != nil {
			lMessaging.Errorf("could not decode metadata with key %s: %s", models.CAMetadataMonitoringExpirationDeltasKey, err)
			return false
		}

		if !hasKey {
			return false
		}

		idx := slices.IndexFunc(deltas, func(med models.MonitoringExpirationDelta) bool {
			if med.Name == key && med.Triggered {
				return true
			}
			return false
		})

		return idx != -1
	}

	criticalTriggered := checkIfTriggered(certUpdate.Updated, "Critical")
	if criticalTriggered {
		prevCriticalTriggered := checkIfTriggered(certUpdate.Previous, "Critical")
		if !prevCriticalTriggered {
			//no update
			dev.IdentitySlot.Status = models.SlotAboutToExpire
			_, err = svc.UpdateDeviceIdentitySlot(services.UpdateDeviceIdentitySlotInput{
				ID:   deviceID,
				Slot: *dev.IdentitySlot,
			})
			if err != nil {
				err = fmt.Errorf("could not update ID slot to critical for device %s: %s", deviceID, err)
				lMessaging.Error(err)
				return err
			}
		}
	}

	preventiveTriggered := checkIfTriggered(certUpdate.Updated, "Preventive")
	if preventiveTriggered {
		prevPreventiveTriggered := checkIfTriggered(certUpdate.Previous, "Preventive")
		if !prevPreventiveTriggered {
			//no update
			dev.IdentitySlot.Status = models.SlotRenewalWindow
			_, err = svc.UpdateDeviceIdentitySlot(services.UpdateDeviceIdentitySlotInput{
				ID:   deviceID,
				Slot: *dev.IdentitySlot,
			})
			if err != nil {
				err = fmt.Errorf("could not update ID slot to preventive for device %s: %s", deviceID, err)
				lMessaging.Error(err)
				return err
			}
		}
	}

	return nil
}

func createDevicesStorageInstance(logger *logrus.Entry, conf config.PluggableStorageEngine) (storage.DeviceManagerRepo, error) {
	switch conf.Provider {
	case config.Postgres:
		psqlCli, err := postgres.CreatePostgresDBConnection(logger, conf.Postgres, "devicemanager")
		if err != nil {
			return nil, fmt.Errorf("could not create postgres client: %s", err)
		}

		deviceStore, err := postgres.NewDeviceManagerRepository(psqlCli)
		if err != nil {
			return nil, fmt.Errorf("could not initialize postgres Device client: %s", err)
		}

		return deviceStore, nil
	case config.CouchDB:
		couchdbClient, err := couchdb.CreateCouchDBConnection(logger, conf.CouchDB)
		if err != nil {
			return nil, fmt.Errorf("could not create couchdb client: %s", err)
		}

		deviceStore, err := couchdb.NewCouchDeviceRepository(couchdbClient)
		if err != nil {
			return nil, fmt.Errorf("could not initialize couchdb Device client: %s", err)
		}

		return deviceStore, nil
	}

	return nil, fmt.Errorf("no storage engine")
}
