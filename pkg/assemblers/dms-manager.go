package assemblers

import (
	"fmt"

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

func AssembleDMSManagerServiceWithHTTPServer(conf config.DMSconfig, caService services.CAService, deviceService services.DeviceManagerService, serviceInfo models.APIServiceInfo) (*services.DMSManagerService, int, error) {
	service, err := AssembleDMSManagerService(conf, caService, deviceService)
	if err != nil {
		return nil, -1, fmt.Errorf("could not assemble DMS Manager Service. Exiting: %s", err)
	}

	lHttp := helpers.ConfigureLogger(conf.Server.LogLevel, "HTTP Server")

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
	lSvc := helpers.ConfigureLogger(conf.Logs.Level, "Service")
	lMessage := helpers.ConfigureLogger(conf.EventBus.LogLevel, "Event Bus")
	lStorage := helpers.ConfigureLogger(conf.Storage.LogLevel, "Storage")

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

	dmsSvc := svc.(*services.DMSManagerServiceImpl)

	if conf.EventBus.Enabled {
		log.Infof("Event Bus is enabled")
		eventBus, err := messaging.NewMessagingEngine(lMessage, conf.EventBus, "dms-manager")
		if err != nil {
			return nil, fmt.Errorf("could not setup event bus: %s", err)
		}

		svc = eventpub.NewDMSEventPublisher(eventBus)(svc)
	} //this utilizes the middlewares from within the CA service (if svc.Service.func is uses instead of regular svc.func)
	dmsSvc.SetService(svc)

	return &svc, nil
}

func createDMSStorageInstance(logger *log.Entry, conf config.PluggableStorageEngine) (storage.DMSRepo, error) {
	switch conf.Provider {
	case config.Postgres:
		psqlCli, err := postgres.CreatePostgresDBConnection(logger, conf.Postgres, "dmsmanager")
		if err != nil {
			return nil, fmt.Errorf("could not create postgres client: %s", err)
		}

		dmsStore, err := postgres.NewDMSManagerRepository(psqlCli)
		if err != nil {
			return nil, fmt.Errorf("could not initialize postgres DMS client: %s", err)
		}

		return dmsStore, nil
	case config.CouchDB:
		couchdbClient, err := couchdb.CreateCouchDBConnection(logger, conf.CouchDB)
		if err != nil {
			return nil, fmt.Errorf("could not create couchdb client: %s", err)
		}

		dmsStore, err := couchdb.NewCouchDMSRepository(couchdbClient)
		if err != nil {
			return nil, fmt.Errorf("could not initialize couchdb DMS client: %s", err)
		}

		return dmsStore, nil
	}

	return nil, fmt.Errorf("no storage engine")
}
