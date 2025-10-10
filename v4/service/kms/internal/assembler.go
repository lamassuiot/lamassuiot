package internal

import (
	"fmt"

	cebuilder "github.com/lamassuiot/lamassuiot/backend/v3/pkg/cryptoengines/builder"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/eventbus"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/storage/builder"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/eventpublisher"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/service/kms"
	"github.com/lamassuiot/lamassuiot/service/kms/internal/middlewares/eventpub"
	log "github.com/sirupsen/logrus"
)

func AssembleKMSServiceWithHTTPServer(conf ServiceConfig, serviceInfo models.APIServiceInfo) (*kms.KMSService, int, error) {
	service, err := AssembleKMSService(conf)
	if err != nil {
		return nil, -1, fmt.Errorf("could not assemble Service. Exiting: %s", err)
	}

	lHttp := helpers.SetupLogger(conf.Server.LogLevel, kms.SHORT_SERVICE_IDENTIFIER, "HTTP Server")

	httpEngine := routes.NewGinEngine(lHttp)
	httpGrp := httpEngine.Group("/")
	NewKMSHTTPLayer(httpGrp, *service)
	port, err := RunHttpRouter(lHttp, httpEngine, conf.Server, serviceInfo)
	if err != nil {
		return nil, -1, fmt.Errorf("could not run Service http server: %s", err)
	}

	return service, port, nil
}

func AssembleCAService(conf ServiceConfig) (*kms.KMSService, error) {
	lSvc := helpers.SetupLogger(conf.Logs.Level, "CA", "Service")
	lMessage := helpers.SetupLogger(conf.PublisherEventBus.LogLevel, "CA", "Event Bus")
	lAudit := helpers.SetupLogger(conf.PublisherEventBus.LogLevel, "CA", "Audit Bus")

	lStorage := helpers.SetupLogger(conf.Storage.LogLevel, "CA", "Storage")
	lCryptoEng := helpers.SetupLogger(conf.CryptoEngineConfig.LogLevel, "CA", "CryptoEngine")

	engines, err := createCryptoEngines(lCryptoEng, conf)
	if err != nil {
		return nil, fmt.Errorf("could not create crypto engines: %s", err)
	}

	for engineID, engine := range engines {
		logEntry := log.NewEntry(log.StandardLogger())
		if engine.Default {
			logEntry = log.WithField("subsystem-provider", "DEFAULT ENGINE")

		}

		logEntry.Infof("loaded %s engine with id %s", engine.Service.GetEngineConfig().Type, engineID)

		if conf.CryptoEngineConfig.MigrateKeysFormat {
			//TODO: implement or decide how to handle key format migration.
			//V3 uses a key format depending on the certificate SKI, but this service no longer mounts certificates repo.
			logEntry.Fatal("key format migration is not supported in KMS service")
		}
	}

	kmsStorage, err := createKMSStorageInstance(lStorage, conf.Storage)
	if err != nil {
		return nil, fmt.Errorf("could not create KMS storage instance: %s", err)
	}

	svc, err := NewKMSService(KMSServiceBuilder{
		Logger:        lSvc,
		CryptoEngines: engines,
		KMSStorage:    kmsStorage,
	})
	if err != nil {
		return nil, fmt.Errorf("could not create CA service: %v", err)
	}

	castedSvc := svc.(*KMSServiceBackend)

	if conf.PublisherEventBus.Enabled {
		log.Infof("Event Bus is enabled")
		pub, err := eventbus.NewEventBusPublisher(conf.PublisherEventBus, "ca", lMessage)
		if err != nil {
			return nil, fmt.Errorf("could not create Event Bus publisher: %s", err)
		}

		eventPublisher := &eventpublisher.CloudEventPublisher{
			Publisher: pub,
			ServiceID: kms.SHORT_SERVICE_IDENTIFIER,
			Logger:    lMessage,
		}

		auditPublisher := &eventpublisher.CloudEventPublisher{
			Publisher: pub,
			ServiceID: kms.SHORT_SERVICE_IDENTIFIER,
			Logger:    lAudit,
		}

		svc = eventpub.NewKMSEventBusPublisher(eventPublisher)(svc)
		svc = eventpub.NewKMSAuditEventBusPublisher(*eventpublisher.NewAuditPublisher(auditPublisher))(svc)

		//this utilizes the middlewares from within the CA service (if svc.service.func is used instead of regular svc.func)
		castedSvc.SetService(svc)
	}

	return &svc, nil
}

func createKMSStorageInstance(logger *log.Entry, conf cconfig.PluggableStorageEngine) (KMSKeysRepo, error) {
	engine, err := builder.BuildStorageEngine(logger, conf)
	if err != nil {
		return nil, fmt.Errorf("could not create storage engine: %s", err)
	}

	kmsStorage, err := engine.GetKMSStorage()
	if err != nil {
		return nil, fmt.Errorf("could not get KMS storage: %s", err)
	}

	return kmsStorage, nil
}

func createCryptoEngines(logger *log.Entry, conf ServiceConfig) (map[string]*Engine, error) {
	engines := map[string]*Engine{}

	for _, cfg := range conf.CryptoEngineConfig.CryptoEngines {
		engine, err := cebuilder.BuildCryptoEngine(logger, cfg)

		if err != nil {
			log.Warnf("skipping engine with id %s of type %s. Can not create engine: %s", cfg.ID, cfg.Type, err)
		} else {
			engines[cfg.ID] = &Engine{
				Default: cfg.ID == conf.CryptoEngineConfig.DefaultEngine,
				Service: engine,
			}
		}
	}

	return engines, nil
}
