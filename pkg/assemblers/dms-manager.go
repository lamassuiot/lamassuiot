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
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage/builder"
	log "github.com/sirupsen/logrus"
)

func AssembleDMSManagerServiceWithHTTPServer(conf config.DMSconfig, caService services.CAService, deviceService services.DeviceManagerService, serviceInfo models.APIServiceInfo) (*services.DMSManagerService, int, error) {
	service, err := AssembleDMSManagerService(conf, caService, deviceService)
	if err != nil {
		return nil, -1, fmt.Errorf("could not assemble DMS Manager Service. Exiting: %s", err)
	}

	lHttp := helpers.SetupLogger(conf.Server.LogLevel, "DMS Manager", "HTTP Server")

	httpEngine := routes.NewGinEngine(lHttp)
	httpGrp := httpEngine.Group("/")
	routes.NewDMSManagerHTTPLayer(lHttp, httpGrp, *service)
	port, err := routes.RunHttpRouter(lHttp, httpEngine, conf.Server, serviceInfo)
	if err != nil {
		return nil, -1, fmt.Errorf("could not run DMS Manager http server: %s", err)
	}

	return service, port, nil
}

func AssembleDMSManagerService(conf config.DMSconfig, caService services.CAService, deviceService services.DeviceManagerService) (*services.DMSManagerService, error) {
	lSvc := helpers.SetupLogger(conf.Logs.Level, "DMS Manager", "Service")
	lMessaging := helpers.SetupLogger(conf.PublisherEventBus.LogLevel, "DMS Manager", "Event Bus")
	lStorage := helpers.SetupLogger(conf.Storage.LogLevel, "DMS Manager", "Storage")

	downCert, err := helpers.ReadCertificateFromFile(conf.DownstreamCertificateFile)
	if err != nil {
		return nil, fmt.Errorf("could not read downstream certificate: %s", err)
	}

	devStorage, err := createDMSStorageInstance(lStorage, conf.Storage)
	if err != nil {
		return nil, fmt.Errorf("could not create dms storage instance: %s", err)
	}

	svc := services.NewDMSManagerService(services.DMSManagerBuilder{
		Logger:                lSvc,
		DMSStorage:            devStorage,
		CAClient:              caService,
		DevManagerCli:         deviceService,
		DownstreamCertificate: downCert,
	})

	dmsSvc := svc.(*services.DMSManagerServiceBackend)

	if conf.PublisherEventBus.Enabled {
		log.Infof("Event Bus is enabled")
		pub, err := eventbus.NewEventBusPublisher(conf.PublisherEventBus, "dms-manager", lMessaging)
		if err != nil {
			return nil, fmt.Errorf("could not create Event Bus publisher: %s", err)
		}

		svc = eventpub.NewDMSEventPublisher(&eventpub.CloudEventMiddlewarePublisher{
			Publisher: pub,
			ServiceID: "dms-manager",
			Logger:    lMessaging,
		})(svc)
	} //this utilizes the middlewares from within the CA service (if svc.Service.func is uses instead of regular svc.func)
	dmsSvc.SetService(svc)

	return &svc, nil
}

func createDMSStorageInstance(logger *log.Entry, conf config.PluggableStorageEngine) (storage.DMSRepo, error) {
	storage, err := builder.BuildStorageEngine(logger, conf)
	if err != nil {
		return nil, fmt.Errorf("could not create storage engine: %s", err)
	}
	dmsStorage, err := storage.GetDMSStorage()
	if err != nil {
		return nil, fmt.Errorf("could not get device storage: %s", err)
	}
	return dmsStorage, nil
}
