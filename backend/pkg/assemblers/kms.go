package assemblers

import (
	"context"
	"fmt"

	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/specs"
	cebuilder "github.com/lamassuiot/lamassuiot/v4/backend/pkg/cryptoengines/builder"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/eventbus"
	auditpub "github.com/lamassuiot/lamassuiot/v4/backend/pkg/middlewares/audit"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/middlewares/eventpub"
	otel "github.com/lamassuiot/lamassuiot/v4/backend/pkg/middlewares/otel"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/routes"
	lservices "github.com/lamassuiot/lamassuiot/v4/backend/pkg/services"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/storage/builder"
	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	sdk "github.com/lamassuiot/lamassuiot/v4/sdk"
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
	routes.NewKMSHTTPLayer(httpGrp, *kmsService, conf.AuthzClient, lHttp)

	var openApiContent []byte
	if conf.OpenAPI.Enabled {
		openApiContent = specs.KMS
	}

	port, err := routes.RunHttpRouter(lHttp, httpEngine, conf.Server, serviceInfo, openApiContent)
	if err != nil {
		return nil, -1, fmt.Errorf("could not run KMS Service http server: %s", err)
	}

	return kmsService, port, nil
}

func AssembleKMSService(conf config.KMSConfig) (*services.KMSService, error) {
	sdk.InitOtelSDK(context.Background(), "KMS Service", conf.OtelConfig)

	lSvc := helpers.SetupLogger(conf.Logs.Level, "KMS", "Service")
	lMessage := helpers.SetupLogger(conf.PublisherEventBus.LogLevel, "KMS", "Event Bus")
	lAudit := helpers.SetupLogger(conf.PublisherEventBus.LogLevel, "KMS", "Audit Bus")

	lStorage := helpers.SetupLogger(conf.Storage.LogLevel, "KMS", "Storage")
	lCryptoEng := helpers.SetupLogger(conf.CryptoEngineConfig.LogLevel, "KMS", "CryptoEngine")

	kmsStorage, err := createKMSStorageInstance(lStorage, conf.Storage)
	if err != nil {
		return nil, fmt.Errorf("could not create CA storage instance: %s", err)
	}

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
	}

	if conf.CryptoEngineConfig.MigrateKeysFormat {
		renamed := lservices.NormalizeKeyNames(context.Background(), lSvc, kmsStorage, engines)
		lSvc.Infof("renamed %d keys to their digest", renamed)
	}

	svc, err := lservices.NewKMSService(lservices.KMSServiceBuilder{
		Logger:        lSvc,
		KMSStorage:    kmsStorage,
		CryptoEngines: engines,
	})
	if err != nil {
		return nil, fmt.Errorf("could not create KMS service: %v", err)
	}

	kmsSvc := svc.(*lservices.KMSServiceBackend)

	// Add OTel Middleware
	svc = otel.NewKMSOTelTracer()(svc)
	kmsSvc.SetService(svc)

	if conf.PublisherEventBus.Enabled {
		log.Infof("Event Bus is enabled")
		pub, err := eventbus.NewEventBusPublisher(conf.PublisherEventBus, "kms", lMessage)
		if err != nil {
			return nil, fmt.Errorf("could not create Event Bus publisher: %s", err)
		}

		eventPublisher := &eventpub.CloudEventPublisher{
			Publisher: pub,
			ServiceID: "kms",
			Logger:    lMessage,
		}

		auditPublisher := &eventpub.CloudEventPublisher{
			Publisher: pub,
			ServiceID: "kms",
			Logger:    lAudit,
		}

		svc = eventpub.NewKMSEventBusPublisher(eventPublisher)(svc)
		svc = auditpub.NewKMSAuditEventBusPublisher(*auditpub.NewAuditPublisher(auditPublisher))(svc)

		//this utilizes the middlewares from within the KMS service (if svc.service.func is used instead of regular svc.func)
		kmsSvc.SetService(svc)
	}

	return &svc, nil
}

func createKMSStorageInstance(logger *log.Entry, conf cconfig.PluggableStorageEngine) (storage.KMSKeysRepo, error) {
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

func createCryptoEngines(logger *log.Entry, conf config.KMSConfig) (map[string]*lservices.Engine, error) {
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

// NormalizeKMSKeyNames renames, in their engine and in the KMS, the keys whose key_id is not the digest
// of their public key, as starting the KMS with crypto_engines.migrate_keys_format does.
func NormalizeKMSKeyNames(ctx context.Context, conf config.KMSConfig) (int, error) {
	logger := helpers.SetupLogger(conf.Logs.Level, "KMS", "Key Names")

	kmsStorage, err := createKMSStorageInstance(helpers.SetupLogger(conf.Storage.LogLevel, "KMS", "Storage"), conf.Storage)
	if err != nil {
		return 0, fmt.Errorf("could not create KMS storage instance: %s", err)
	}
	engines, err := createCryptoEngines(helpers.SetupLogger(conf.CryptoEngineConfig.LogLevel, "KMS", "CryptoEngine"), conf)
	if err != nil {
		return 0, fmt.Errorf("could not create crypto engines: %s", err)
	}

	return lservices.NormalizeKeyNames(ctx, logger, kmsStorage, engines), nil
}
