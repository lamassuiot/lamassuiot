package assemblers

import (
	"context"
	"fmt"
	"slices"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/messaging"
	"github.com/lamassuiot/lamassuiot/v2/pkg/middlewares/eventpub"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/routes"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage/couchdb"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage/postgres"
	log "github.com/sirupsen/logrus"
)

func AssembleDeviceManagerServiceWithHTTPServer(conf config.DeviceManagerConfig, caService services.CAService, serviceInfo models.APIServiceInfo) (*services.DeviceManagerService, int, error) {
	service, err := AssembleDeviceManagerService(conf, caService)
	if err != nil {
		return nil, -1, fmt.Errorf("could not assemble Device Manager Service. Exiting: %s", err)
	}

	lHttp := helpers.ConfigureLogger(conf.Server.LogLevel, "HTTP Server")

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
	lSvc := helpers.ConfigureLogger(conf.Logs.Level, "Service")

	lMessaging := helpers.ConfigureLogger(conf.EventBus.LogLevel, "Messaging")
	lStorage := helpers.ConfigureLogger(conf.Storage.LogLevel, "Storage")

	devStorage, err := createDevicesStorageInstance(lStorage, conf.Storage)
	if err != nil {
		return nil, fmt.Errorf("could not create device storage: %s", err)
	}

	svc := services.NewDeviceManagerService(services.DeviceManagerBuilder{
		Logger:         lSvc,
		DevicesStorage: devStorage,
		CAClient:       caService,
	})

	deviceSvc := svc.(*services.DeviceManagerServiceImpl)

	if conf.EventBus.Enabled {
		log.Infof("Event Bus is enabled")
		eventBus, err := messaging.NewMessagingEngine(lMessaging, conf.EventBus, "device-manager")
		if err != nil {
			return nil, fmt.Errorf("could not setup event bus: %s", err)
		}

		svc = eventpub.NewDeviceEventPublisher(eventBus)(svc)
		deviceSvc.SetService(svc)

		updateCertStatusSub, err := eventBus.Subscriber.Subscribe(context.Background(), string(models.EventUpdateCertificateStatusKey))
		go func() {
			for {
				select {
				case message := <-updateCertStatusSub:
					event, err := messaging.ParseCloudEvent(message.Payload)
					if err != nil {
						lMessaging.Errorf("something went wrong while processing cloud event: %s", err)
						message.Ack()
						continue
					}
					cert, err := getEventBody[models.UpdateModel[models.Certificate]](event)
					if err != nil {
						lMessaging.Errorf("could not decode cloud event: %s", err)
						message.Ack()
						return
					}

					deviceID := cert.Updated.Certificate.Subject.CommonName
					dev, err := svc.GetDeviceByID(services.GetDeviceByIDInput{
						ID: deviceID,
					})
					if err != nil {
						lMessaging.Errorf("could not get device %s: %s", deviceID, err)
						message.Ack()
						continue
					}

					var attachedBy models.CAAttachedToDevice
					hasKey, err := helpers.GetMetadataToStruct(cert.Updated.Metadata, models.CAAttachedToDeviceKey, &attachedBy)
					if err != nil {
						lMessaging.Errorf("could not decode metadata with key %s: %s", models.CAAttachedToDeviceKey, err)
						message.Ack()
						continue
					}

					if !hasKey {
						lMessaging.Tracef("skipping event %s, Certificate doesn't have %s key", event.Type(), models.CAAttachedToDeviceKey)
						message.Ack()
						return
					}

					if dev.IdentitySlot.Secrets[dev.IdentitySlot.ActiveVersion] != cert.Updated.SerialNumber {
						//event is not for the active certificate. Skip
						message.Ack()
						continue
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
							lMessaging.Errorf("could not update ID slot to preventive for device %s: %s", deviceID, err)
							message.Ack()
							continue
						}
					}

					message.Ack()
				}
			}
		}()

		updateCertMetaSub, err := eventBus.Subscriber.Subscribe(context.Background(), string(models.EventUpdateCertificateMetadataKey))
		go func() {
			for {
				select {
				case message := <-updateCertMetaSub:
					event, err := messaging.ParseCloudEvent(message.Payload)
					if err != nil {
						lMessaging.Errorf("something went wrong while processing cloud event: %s", err)
						message.Ack()
						continue
					}

					certUpdate, err := getEventBody[models.UpdateModel[models.Certificate]](event)
					if err != nil {
						lMessaging.Errorf("could not decode cloud event: %s", err)
						message.Ack()
						return
					}

					deviceID := certUpdate.Updated.Subject.CommonName
					dev, err := svc.GetDeviceByID(services.GetDeviceByIDInput{
						ID: deviceID,
					})
					if err != nil {
						lMessaging.Errorf("could not get device %s: %s", deviceID, err)
						message.Ack()
						continue
					}

					if dev.IdentitySlot != nil && dev.IdentitySlot.Secrets[dev.IdentitySlot.ActiveVersion] != certUpdate.Updated.SerialNumber {
						//event is not for the active certificate. Skip
						message.Ack()
						continue
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

						if idx == -1 {
							return false
						}

						return true
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
								lMessaging.Errorf("could not update ID slot to critical for device %s: %s", deviceID, err)
								message.Ack()
								continue
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
								lMessaging.Errorf("could not update ID slot to preventive for device %s: %s", deviceID, err)
								message.Ack()
								continue
							}
						}
					}
					message.Ack()
				}
			}
		}()
	}

	return &svc, nil
}

func createDevicesStorageInstance(logger *log.Entry, conf config.PluggableStorageEngine) (storage.DeviceManagerRepo, error) {
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
