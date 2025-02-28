package assemblers

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	cebuilder "github.com/lamassuiot/lamassuiot/backend/v3/pkg/cryptoengines/builder"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/storage/builder"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	core "github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	log "github.com/sirupsen/logrus"
)

func AssembleAsymmetricKMSServiceWithHTTPServer(conf config.AsymmetricKMSConfig, serviceInfo models.APIServiceInfo) (*core.AsymmetricKMSService, int, error) {
	service, err := AssembleAsymmetricKMSService(conf)
	if err != nil {
		return nil, -1, fmt.Errorf("could not assemble Asymmetric KMS Service. Exiting: %s", err)
	}

	return service, -1, nil

	// lHttp := helpers.SetupLogger(conf.Server.LogLevel, "Asymmetric KMS", "HTTP Server")

	// httpEngine := routes.NewGinEngine(lHttp)
	// httpGrp := httpEngine.Group("/")
	// routes.NewAlertsHTTPLayer(httpGrp, *service)
	// port, err := routes.RunHttpRouter(lHttp, httpEngine, conf.Server, serviceInfo)
	// if err != nil {
	// 	return nil, -1, fmt.Errorf("could not run Asymmetric KMS http server: %s", err)
	// }

	// return service, port, nil
}

func AssembleAsymmetricKMSService(conf config.AsymmetricKMSConfig) (*core.AsymmetricKMSService, error) {
	lSvc := helpers.SetupLogger(conf.Logs.Level, "Asymmetric KMS", "Service")
	// lMessaging := helpers.SetupLogger(conf.SubscriberEventBus.LogLevel, "Asymmetric KMS", "Event Bus")

	// Create the storage engine
	lStorage := helpers.SetupLogger(conf.Storage.LogLevel, "Asymmetric KMS", "Storage")
	storageEngine, err := builder.BuildStorageEngine(lStorage, conf.Storage)
	if err != nil {
		return nil, fmt.Errorf("could not create storage engine: %s", err)
	}

	kmsStore, err := storageEngine.GetAsymmetricKMSStorage()
	if err != nil {
		return nil, fmt.Errorf("could not get subscriptions storage: %s", err)
	}

	// Create the crypto engines
	lCryptoEng := helpers.SetupLogger(conf.CryptoEngineConfig.LogLevel, "CA", "CryptoEngine")
	engines, err := createCryptoEngines(lCryptoEng, conf.CryptoEngineConfig)
	if err != nil {
		return nil, fmt.Errorf("could not create crypto engines: %s", err)
	}

	for engineID, engine := range engines {
		logEntry := log.NewEntry(log.StandardLogger())
		if engineID == conf.CryptoEngineConfig.DefaultEngine {
			logEntry = log.WithField("subsystem-provider", "DEFAULT ENGINE")
		}

		ce := *engine
		logEntry.Infof("loaded %s engine with id %s", ce.GetEngineConfig().Type, engineID)
	}

	svc := services.NewAsymmetricKMSServiceBackend(services.AsymmetricKMSServiceBackendBuilder{
		Logger:   lSvc,
		KMSStore: kmsStore,
		Engines:  engines,
	})

	return &svc, nil
}

func createCryptoEngines(logger *log.Entry, conf config.CryptoEngines) (map[string]*cryptoengines.CryptoEngine, error) {
	engines := map[string]*cryptoengines.CryptoEngine{}

	for _, cfg := range conf.CryptoEngines {
		engine, err := cebuilder.BuildCryptoEngine(logger, cfg)

		if err != nil {
			log.Warnf("skipping engine with id %s of type %s. Can not create engine: %s", cfg.ID, cfg.Type, err)
		} else {
			engines[cfg.ID] = &engine
		}
	}

	return engines, nil
}
