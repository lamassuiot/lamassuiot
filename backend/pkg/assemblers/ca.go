package assemblers

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/v3/backend/pkg/config"
	cebuilder "github.com/lamassuiot/lamassuiot/v3/backend/pkg/cryptoengines/builder"
	"github.com/lamassuiot/lamassuiot/v3/backend/pkg/eventbus"
	"github.com/lamassuiot/lamassuiot/v3/backend/pkg/jobs"
	"github.com/lamassuiot/lamassuiot/v3/backend/pkg/middlewares/eventpub"
	"github.com/lamassuiot/lamassuiot/v3/backend/pkg/routes"
	lservices "github.com/lamassuiot/lamassuiot/v3/backend/pkg/services"
	"github.com/lamassuiot/lamassuiot/v3/backend/pkg/storage/builder"
	"github.com/lamassuiot/lamassuiot/v3/backend/pkg/x509engines"
	cconfig "github.com/lamassuiot/lamassuiot/v3/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/services"
	log "github.com/sirupsen/logrus"
)

func AssembleCAServiceWithHTTPServer(conf config.CAConfig, serviceInfo models.APIServiceInfo) (*services.CAService, *jobs.JobScheduler, int, error) {
	caService, scheduler, err := AssembleCAService(conf)
	if err != nil {
		return nil, nil, -1, fmt.Errorf("could not assemble CA Service. Exiting: %s", err)
	}

	lHttp := helpers.SetupLogger(conf.Server.LogLevel, "CA", "HTTP Server")

	httpEngine := routes.NewGinEngine(lHttp)
	httpGrp := httpEngine.Group("/")
	routes.NewCAHTTPLayer(httpGrp, *caService)
	port, err := routes.RunHttpRouter(lHttp, httpEngine, conf.Server, serviceInfo)
	if err != nil {
		return nil, nil, -1, fmt.Errorf("could not run CA Service http server: %s", err)
	}

	return caService, scheduler, port, nil
}

func AssembleCAService(conf config.CAConfig) (*services.CAService, *jobs.JobScheduler, error) {
	lSvc := helpers.SetupLogger(conf.Logs.Level, "CA", "Service")
	lMessage := helpers.SetupLogger(conf.PublisherEventBus.LogLevel, "CA", "Event Bus")
	lStorage := helpers.SetupLogger(conf.Storage.LogLevel, "CA", "Storage")
	lCryptoEng := helpers.SetupLogger(conf.CryptoEngineConfig.LogLevel, "CA", "CryptoEngine")
	lMonitor := helpers.SetupLogger(conf.Logs.Level, "CA", "Crypto Monitoring")

	engines, err := createCryptoEngines(lCryptoEng, conf)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create crypto engines: %s", err)
	}

	for engineID, engine := range engines {
		logEntry := log.NewEntry(log.StandardLogger())
		if engine.Default {
			logEntry = log.WithField("subsystem-provider", "DEFAULT ENGINE")

		}
		logEntry.Infof("loaded %s engine with id %s", engine.Service.GetEngineConfig().Type, engineID)
	}

	caStorage, certStorage, err := createCAStorageInstance(lStorage, conf.Storage)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create CA storage instance: %s", err)
	}

	svc, err := lservices.NewCAService(lservices.CAServiceBuilder{
		Logger:               lSvc,
		CryptoEngines:        engines,
		CAStorage:            caStorage,
		CertificateStorage:   certStorage,
		CryptoMonitoringConf: conf.CryptoMonitoring,
		VAServerDomain:       conf.VAServerDomain,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("could not create CA service: %v", err)
	}

	caSvc := svc.(*lservices.CAServiceBackend)

	if conf.PublisherEventBus.Enabled {
		log.Infof("Event Bus is enabled")
		pub, err := eventbus.NewEventBusPublisher(conf.PublisherEventBus, "ca", lMessage)
		if err != nil {
			return nil, nil, fmt.Errorf("could not create Event Bus publisher: %s", err)
		}

		eventpublisher := &eventpub.CloudEventMiddlewarePublisher{
			Publisher: pub,
			ServiceID: "ca",
			Logger:    lMessage,
		}

		svc = eventpub.NewCAEventBusPublisher(eventpublisher)(svc)
	}

	var scheduler *jobs.JobScheduler
	if conf.CryptoMonitoring.Enabled {
		log.Infof("Crypto Monitoring is enabled")
		monitorJob := jobs.NewCryptoMonitor(svc, lMonitor)
		scheduler = jobs.NewJobScheduler(conf.CryptoMonitoring, lMonitor, monitorJob)
		scheduler.Start()
	}

	//this utilizes the middlewares from within the CA service (if svc.Service.func is uses instead of regular svc.func)
	caSvc.SetService(svc)

	return &svc, scheduler, nil
}

func createCAStorageInstance(logger *log.Entry, conf cconfig.PluggableStorageEngine) (storage.CACertificatesRepo, storage.CertificatesRepo, error) {
	engine, err := builder.BuildStorageEngine(logger, conf)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create storage engine: %s", err)
	}

	caStorage, err := engine.GetCAStorage()
	if err != nil {
		return nil, nil, fmt.Errorf("could not get CA storage: %s", err)
	}

	certStorage, err := engine.GetCertstorage()
	if err != nil {
		return nil, nil, fmt.Errorf("could not get Cert storage: %s", err)
	}

	return caStorage, certStorage, nil
}

func createCryptoEngines(logger *log.Entry, conf config.CAConfig) (map[string]*lservices.Engine, error) {
	x509engines.SetCryptoEngineLogger(logger) //Important!

	engines := map[string]*lservices.Engine{}

	for _, cfg := range conf.CryptoEngineConfig.CryptoEngines {
		engine, err := cebuilder.BuildCryptoEngine(logger, cfg)

		if err != nil {
			log.Warnf("skipping engine with id %s of type %s. Can not create engine: %s", cfg.ID, cfg.Type, err)
		} else {
			engines[cfg.ID] = &lservices.Engine{
				Default: cfg.ID == conf.CryptoEngineConfig.DefaultEngine,
				Service: engine,
			}
		}
	}

	return engines, nil
}
