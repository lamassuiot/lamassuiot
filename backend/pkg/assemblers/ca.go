package assemblers

import (
	"fmt"
	"unicode"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	cebuilder "github.com/lamassuiot/lamassuiot/backend/v3/pkg/cryptoengines/builder"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/eventbus"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/jobs"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/middlewares/eventpub"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes"
	lservices "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/storage/builder"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/engines/crypto/software/v3"
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
		if conf.CryptoEngineConfig.MigrateKeysFormat {
			err = migrateKeysToV2Format(lSvc, engine, engineID)
			if err != nil {
				return nil, nil, fmt.Errorf("could not migrate %s engine keys to v2 format: %s", engineID, err)
			}
		}
	}

	caStorage, certStorage, caCertRequestStorage, err := createCAStorageInstance(lStorage, conf.Storage)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create CA storage instance: %s", err)
	}

	svc, err := lservices.NewCAService(lservices.CAServiceBuilder{
		Logger:                      lSvc,
		CryptoEngines:               engines,
		CAStorage:                   caStorage,
		CertificateStorage:          certStorage,
		CACertificateRequestStorage: caCertRequestStorage,
		VAServerDomains:             conf.VAServerDomains,
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
	if conf.CertificateMonitoringJob.Enabled {
		log.Infof("Crypto Monitoring is enabled")
		monitorJob := jobs.NewCryptoMonitor(svc, lMonitor)
		scheduler = jobs.NewJobScheduler(lMonitor, conf.CertificateMonitoringJob.Frequency, monitorJob)
		scheduler.Start()
	}

	//this utilizes the middlewares from within the CA service (if svc.Service.func is uses instead of regular svc.func)
	caSvc.SetService(svc)

	return &svc, scheduler, nil
}

func createCAStorageInstance(logger *log.Entry, conf cconfig.PluggableStorageEngine) (storage.CACertificatesRepo, storage.CertificatesRepo, storage.CACertificateRequestRepo, error) {
	engine, err := builder.BuildStorageEngine(logger, conf)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not create storage engine: %s", err)
	}

	caStorage, err := engine.GetCAStorage()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not get CA storage: %s", err)
	}

	certStorage, err := engine.GetCertstorage()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not get Cert storage: %s", err)
	}

	caCertRequestStorage, err := engine.GetCACertificateRequestStorage()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not get CA Certificate Request storage: %s", err)
	}

	return caStorage, certStorage, caCertRequestStorage, nil
}

func createCryptoEngines(logger *log.Entry, conf config.CAConfig) (map[string]*lservices.Engine, error) {
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

func migrateKeysToV2Format(logger *log.Entry, engine *lservices.Engine, engineID string) error {
	// Check if engine keys should be renamed
	keyIDs, err := engine.Service.ListPrivateKeyIDs()
	if err != nil {
		return nil
	}
	keyMigLog := logger.WithField("engine", engineID)
	softCrypto := software.NewSoftwareCryptoEngine(keyMigLog)
	keyMigLog.Infof("checking engine keys format")

	for _, keyID := range keyIDs {
		// check if they are in V1 format (serial number).
		// V2 format is the hex encoded SHA256 of the public key, a string of 64 characters
		containsNonHex := false
		for _, char := range keyID {
			if !unicode.IsLetter(char) && !unicode.IsDigit(char) {
				// Not a hex character. Exit loop
				containsNonHex = true
				break
			}
		}

		if len(keyID) != 64 || containsNonHex {
			// Transform to V2 format
			key, err := engine.Service.GetPrivateKeyByID(keyID)
			if err != nil {
				return fmt.Errorf("could not get key %s: %w", keyID, err)
			}

			newKeyID, err := softCrypto.EncodePKIXPublicKeyDigest(key.Public())
			if err != nil {
				return fmt.Errorf("could not encode public key digest: %w", err)
			}

			keyMigLog.Debugf("renaming key %s to %s", keyID, newKeyID)
			err = engine.Service.RenameKey(keyID, newKeyID)
			if err != nil {
				return fmt.Errorf("could not rename key %s: %w", keyID, err)
			}
		}
	}
	return nil
}
