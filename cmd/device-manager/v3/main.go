package main

import (
	"fmt"
	"io"

	formatter "github.com/antonfisher/nested-logrus-formatter"
	"github.com/lamassuiot/lamassuiot/pkg/v3/clients"
	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
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

	conf, err := config.LoadConfig[config.DeviceManagerConfig]()
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

	lSvc := configureLogger(globalLogLevel, conf.Logs.SubsystemLogging.Service, "Service")
	lHttp := configureLogger(globalLogLevel, conf.Logs.SubsystemLogging.HttpTransport, "HTTP Server")
	lStorage := configureLogger(globalLogLevel, conf.Logs.SubsystemLogging.StorageEngine, "Storage")

	devStorage, err := createStorageInstance(lStorage, conf.Storage)
	if err != nil {
		log.Fatal(err)
	}

	lCAClient := configureLogger(globalLogLevel, conf.CAClient.LogLevel, "LMS SDK - CA Client")
	caHttpCli, err := clients.BuildHTTPClient(conf.CAClient.HTTPClient, lCAClient)
	if err != nil {
		log.Fatalf("could not build HTTP CA Client: %s", err)
	}

	caCli := clients.NewHttpCAClient(caHttpCli, fmt.Sprintf("%s://%s%s:%d", conf.CAClient.Protocol, conf.CAClient.Hostname, conf.CAClient.BasePath, conf.CAClient.Port))

	svc := services.NewDeviceManagerService(services.DeviceManagerBuilder{
		Logger:         lSvc,
		DevicesStorage: devStorage,
		CAClient:       caCli,
	})

	deviceSvc := svc.(*services.DeviceManagerServiceImpl)

	//this utilizes the middlewares from within the CA service (if svc.Service.func is uses instead of regular svc.func)
	deviceSvc.SetService(svc)

	err = routes.NewDeviceManagerHTTPLayer(lHttp, svc, conf.Server, models.APIServiceInfo{
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

func createStorageInstance(logger *log.Entry, conf config.PluggableStorageEngine) (storage.DeviceManagerRepo, error) {
	switch conf.Provider {
	case config.Postgres:
		return nil, fmt.Errorf("TODO")
	case config.CouchDB:
		couchdbClient, err := couchdb.CreateCouchDBConnection(logger, conf.CouchDB)
		if err != nil {
			log.Fatalf("could not create couchdb client: %s", err)
		}

		deviceStore, err := couchdb.NewCouchDeviceRepository(couchdbClient)
		if err != nil {
			log.Fatalf("could not initialize couchdb Device client: %s", err)
		}

		return deviceStore, nil
	}

	return nil, fmt.Errorf("no storage engine")
}

func configureLogger(defaultLevel log.Level, currentLevel config.LogLevel, subsystem string) *log.Entry {
	var err error
	logger := log.New()
	logger.SetFormatter(logFormatter)
	lSubsystem := logger.WithField("subsystem", subsystem)
	if currentLevel == config.None {
		lSubsystem.Infof("subsystem logging will be disabled")
		lSubsystem.Logger.SetOutput(io.Discard)
	} else {
		level := defaultLevel

		if currentLevel != "" {
			level, err = log.ParseLevel(string(currentLevel))
			if err != nil {
				log.Warnf("'%s' invalid '%s' log level. Defaulting to global log level", subsystem, currentLevel)
			}
		} else {
			log.Warnf("'%s' log level not set. Defaulting to global log level", subsystem)
		}

		lSubsystem.Logger.SetLevel(level)
	}
	lSubsystem.Infof("log level set to '%s'", lSubsystem.Logger.GetLevel())
	return lSubsystem
}
