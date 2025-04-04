package assemblers

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/eventbus"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/middlewares/eventpub"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes"
	lservices "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/services/ra"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/storage/builder"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	log "github.com/sirupsen/logrus"
)

func AssembleDMSManagerServiceWithHTTPServer(conf config.DMSconfig, caService services.CAService, deviceService services.DeviceManagerService, serviceInfo models.APIServiceInfo) (*services.DMSManagerService, int, error) {
	service, estService, err := AssembleDMSManagerService(conf, caService, deviceService)
	if err != nil {
		return nil, -1, fmt.Errorf("could not assemble DMS Manager Service. Exiting: %s", err)
	}

	lHttp := chelpers.SetupLogger(conf.Server.LogLevel, "DMS Manager", "HTTP Server")

	httpEngine := routes.NewGinEngine(lHttp)
	httpGrp := httpEngine.Group("/")

	routes.NewDMSManagerHTTPLayer(lHttp, httpGrp, *service)
	routes.NewESTHttpRoutes(lHttp, httpGrp, estService)

	port, err := routes.RunHttpRouter(lHttp, httpEngine, conf.Server, serviceInfo)
	if err != nil {
		return nil, -1, fmt.Errorf("could not run DMS Manager http server: %s", err)
	}

	return service, port, nil
}

func AssembleDMSManagerService(conf config.DMSconfig, caService services.CAService, deviceService services.DeviceManagerService) (*services.DMSManagerService, services.ESTService, error) {
	lSvc := chelpers.SetupLogger(conf.Logs.Level, "DMS Manager", "Service")
	lMessaging := chelpers.SetupLogger(conf.PublisherEventBus.LogLevel, "DMS Manager", "Event Bus")
	lStorage := chelpers.SetupLogger(conf.Storage.LogLevel, "DMS Manager", "Storage")

	devStorage, err := createDMSStorageInstance(lStorage, conf.Storage)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create dms storage instance: %s", err)
	}

	svc := lservices.NewDMSManagerService(lservices.DMSManagerBuilder{
		Logger:        lSvc,
		DMSStorage:    devStorage,
		CAClient:      caService,
		DevManagerCli: deviceService,
	})

	dmsSvc := svc.(*lservices.DMSManagerServiceBackend)

	if conf.PublisherEventBus.Enabled {
		log.Infof("Event Bus is enabled")
		pub, err := eventbus.NewEventBusPublisher(conf.PublisherEventBus, "dms-manager", lMessaging)
		if err != nil {
			return nil, nil, fmt.Errorf("could not create Event Bus publisher: %s", err)
		}

		svc = eventpub.NewDMSEventPublisher(&eventpub.CloudEventMiddlewarePublisher{
			Publisher: pub,
			ServiceID: "dms-manager",
			Logger:    lMessaging,
		})(svc)
	} //this utilizes the middlewares from within the CA service (if svc.Service.func is uses instead of regular svc.func)
	dmsSvc.SetService(svc)

	downCert, err := chelpers.ReadCertificateFromFile(conf.DownstreamCertificateFile)
	if err != nil {
		return nil, nil, fmt.Errorf("could not read downstream certificate: %s", err)
	}

	estService := ra.NewESTForRA(ra.ESTBackendBuilder{
		Logger:         lSvc,
		CAService:      caService,
		DeviceManager:  deviceService,
		DMSManager:     dmsSvc,
		DownstreamCert: downCert,
	})

	return &svc, estService, nil
}

func createDMSStorageInstance(logger *log.Entry, conf cconfig.PluggableStorageEngine) (storage.DMSRepo, error) {
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
