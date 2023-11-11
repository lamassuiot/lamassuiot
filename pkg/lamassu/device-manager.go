package lamassu

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/routes"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
	"github.com/lamassuiot/lamassuiot/pkg/v3/storage"
	"github.com/lamassuiot/lamassuiot/pkg/v3/storage/couchdb"
	"github.com/lamassuiot/lamassuiot/pkg/v3/storage/postgres"
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
	// lMessage := helpers.ConfigureLogger(conf.AMQPConnection.LogLevel, "Messaging")
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

	//this utilizes the middlewares from within the DMS service (if svc.Service.func is uses instead of regular svc.func)
	deviceSvc.SetService(svc)

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
