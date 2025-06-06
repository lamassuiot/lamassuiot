package assemblers

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	cebuilder "github.com/lamassuiot/lamassuiot/backend/v3/pkg/cryptoengines/builder"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/eventbus"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/middlewares/eventpub"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes"
	lservices "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	log "github.com/sirupsen/logrus"
)

func AssembleKMSServiceWithHTTPServer(conf config.KMSConfig, serviceInfo models.APIServiceInfo) (*services.KMSService, int, error) {
	kmsService, err := AssembleKMSService(conf)
	if err != nil {
		return nil, -1, fmt.Errorf("could not assemble KMS Service. Exiting: %s", err)
	}

	lHttp := helpers.SetupLogger(conf.Server.LogLevel, "KMS", "HTTP Server")

	httpEngine := routes.NewGinEngine(lHttp)
	httpGrp := httpEngine.Group("/")
	routes.NewKMSHTTPLayer(httpGrp, *kmsService)
	port, err := routes.RunHttpRouter(lHttp, httpEngine, conf.Server, serviceInfo)
	if err != nil {
		return nil, -1, fmt.Errorf("could not run KMS Service http server: %s", err)
	}

	return kmsService, port, nil
}

func AssembleKMSService(conf config.KMSConfig) (*services.KMSService, error) {
	lSvc := helpers.SetupLogger(conf.Logs.Level, "KMS", "Service")
	lMessage := helpers.SetupLogger(conf.PublisherEventBus.LogLevel, "KMS", "Event Bus")
	lCryptoEng := helpers.SetupLogger(conf.CryptoEngineConfig.LogLevel, "CA", "CryptoEngine")

	engines, err := createCryptoEngines(lCryptoEng, nil, &conf)
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
			err = migrateKeysToV2Format(lSvc, engine, engineID)
			if err != nil {
				return nil, fmt.Errorf("could not migrate %s engine keys to v2 format: %s", engineID, err)
			}
		}
	}

	svc, err := lservices.NewKMSService(lservices.KMSServiceBuilder{
		Logger:        lSvc,
		CryptoEngines: engines,
	})
	if err != nil {
		return nil, fmt.Errorf("could not create CA service: %v", err)
	}

	kmsSvc := svc.(*lservices.KMSServiceBackend)

	if conf.PublisherEventBus.Enabled {
		log.Infof("Event Bus is enabled")
		pub, err := eventbus.NewEventBusPublisher(conf.PublisherEventBus, "kms", lMessage)
		if err != nil {
			return nil, fmt.Errorf("could not create Event Bus publisher: %s", err)
		}

		eventpublisher := &eventpub.CloudEventMiddlewarePublisher{
			Publisher: pub,
			ServiceID: "ca",
			Logger:    lMessage,
		}

		svc = eventpub.NewKMSEventBusPublisher(eventpublisher)(svc)
	}

	kmsSvc.SetService(svc)

	return &svc, nil

}

func createCryptoEngines(logger *log.Entry, confCa *config.CAConfig, confKms *config.KMSConfig) (map[string]*lservices.Engine, error) {
	engines := map[string]*lservices.Engine{}

	var cryptoEnginesConf config.CryptoEngines
	if confCa != nil && confCa.CryptoEngineConfig.CryptoEngines != nil && len(confCa.CryptoEngineConfig.CryptoEngines) > 0 {
		cryptoEnginesConf = confCa.CryptoEngineConfig
	} else {
		cryptoEnginesConf = confKms.CryptoEngineConfig
	}

	for _, cfg := range cryptoEnginesConf.CryptoEngines {
		engine, err := cebuilder.BuildCryptoEngine(logger, cfg)
		if err != nil {
			log.Warnf("skipping engine with id %s of type %s. Can not create engine: %s", cfg.ID, cfg.Type, err)
		} else {
			engines[cfg.ID] = &lservices.Engine{
				Default: cfg.ID == cryptoEnginesConf.DefaultEngine,
				Service: engine,
			}
		}
	}

	return engines, nil
}
