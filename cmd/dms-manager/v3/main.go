package main

import (
	"fmt"

	formatter "github.com/antonfisher/nested-logrus-formatter"
	"github.com/lamassuiot/lamassuiot/pkg/v3/clients"
	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/routes"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
	"github.com/lamassuiot/lamassuiot/pkg/v3/storage"
	"github.com/lamassuiot/lamassuiot/pkg/v3/storage/couchdb"
	log "github.com/sirupsen/logrus"
)

var (
	version   string = "v0"    // api version
	sha1ver   string = "-"     // sha1 revision used to build the program
	buildTime string = "devTS" // when the executable was built
)

var logFormatter = &formatter.Formatter{
	TimestampFormat: "2006-01-02 15:04:05",
	HideKeys:        true,
	FieldsOrder:     []string{"subsystem", "subsystem-provider", "req"},
}

func main() {
	log.SetFormatter(logFormatter)

	log.Infof("starting api: version=%s buildTime=%s sha1ver=%s", version, buildTime, sha1ver)

	conf, err := config.LoadConfig[config.DMSconfig]()
	if err != nil {
		log.Fatal(err)
	}

	globalLogLevel, err := log.ParseLevel(string(conf.Logs.Level))
	if err != nil {
		log.Warn("unknown log level. defaulting to 'info' log level")
		globalLogLevel = log.InfoLevel
	}
	log.SetLevel(globalLogLevel)
	log.Infof("global log level set to '%s'", globalLogLevel)

	lSvc := helpers.ConfigureLogger(globalLogLevel, conf.Logs.SubsystemLogging.Service, "Service")
	lHttp := helpers.ConfigureLogger(globalLogLevel, conf.Logs.SubsystemLogging.HttpTransport, "HTTP Server")
	lStorage := helpers.ConfigureLogger(globalLogLevel, conf.Logs.SubsystemLogging.StorageEngine, "Storage")

	lCAClient := helpers.ConfigureLogger(globalLogLevel, conf.CAClient.LogLevel, "LMS SDK - CA Client")
	lDeviceClient := helpers.ConfigureLogger(globalLogLevel, conf.DevManagerClient.LogLevel, "LMS SDK - Device Client")

	devStorage, err := createStorageInstance(lStorage, conf.Storage)
	if err != nil {
		log.Fatal(err)
	}

	caHttpCli, err := clients.BuildHTTPClient(conf.CAClient.HTTPClient, lCAClient)
	if err != nil {
		log.Fatalf("could not build HTTP CA Client: %s", err)
	}

	caCli := clients.NewHttpCAClient(caHttpCli, fmt.Sprintf("%s://%s:%d%s", conf.CAClient.Protocol, conf.CAClient.Hostname, conf.CAClient.Port, conf.CAClient.BasePath))

	deviceHttpCli, err := clients.BuildHTTPClient(conf.DevManagerClient.HTTPClient, lDeviceClient)
	if err != nil {
		log.Fatalf("could not build HTTP Device Client: %s", err)
	}

	deviceCli := clients.NewHttpDeviceManagerClient(deviceHttpCli, fmt.Sprintf("%s://%s:%d%s", conf.DevManagerClient.Protocol, conf.DevManagerClient.Hostname, conf.DevManagerClient.Port, conf.DevManagerClient.BasePath))

	svc := services.NewDMSManagerService(services.DMSManagerBuilder{
		Logger:              lSvc,
		DMSStorage:          devStorage,
		DevManagerCli:       deviceCli,
		CAClient:            caCli,
		DeviceMonitorConfig: conf.DeviceMonitorConfig,
	})

	deviceSvc := svc.(*services.DmsManagerServiceImpl)

	//this utilizes the middlewares from within the CA service (if svc.Service.func is uses instead of regular svc.func)
	deviceSvc.SetService(svc)

	err = routes.NewDMSManagerHTTPLayer(lHttp, svc, conf.Server, models.APIServiceInfo{
		Version:   version,
		BuildSHA:  sha1ver,
		BuildTime: buildTime,
	})
	if err != nil {
		log.Fatal(err)
	}

	forever := make(chan struct{})
	<-forever
}

func createStorageInstance(logger *log.Entry, conf config.PluggableStorageEngine) (storage.DMSRepo, error) {
	switch conf.Provider {
	case config.Postgres:
		return nil, fmt.Errorf("TODO")
	case config.CouchDB:
		couchdbClient, err := couchdb.CreateCouchDBConnection(logger, conf.CouchDB)
		if err != nil {
			log.Fatalf("could not create couchdb client: %s", err)
		}

		dmsStore, err := couchdb.NewCouchDMSRepository(couchdbClient)
		if err != nil {
			log.Fatalf("could not initialize couchdb DMS client: %s", err)
		}

		return dmsStore, nil
	}

	return nil, fmt.Errorf("no storage engine")
}
