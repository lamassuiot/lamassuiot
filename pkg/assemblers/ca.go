package assemblers

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/cryptoengines"
	"github.com/lamassuiot/lamassuiot/v2/pkg/eventbus"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/jobs"
	"github.com/lamassuiot/lamassuiot/v2/pkg/middlewares/eventpub"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/routes"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage/builder"
	"github.com/lamassuiot/lamassuiot/v2/pkg/x509engines"
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
	lCryptoEng := helpers.SetupLogger(conf.CryptoEngines.LogLevel, "CA", "CryptoEngine")
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

	svc, err := services.NewCAService(services.CAServiceBuilder{
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

	caSvc := svc.(*services.CAServiceBackend)

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

func createCAStorageInstance(logger *log.Entry, conf config.PluggableStorageEngine) (storage.CACertificatesRepo, storage.CertificatesRepo, error) {
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

func createCryptoEngines(logger *log.Entry, conf config.CAConfig) (map[string]*services.Engine, error) {
	x509engines.SetCryptoEngineLogger(logger) //Important!

	engines := map[string]*services.Engine{}
	for _, cfg := range conf.CryptoEngines.HashicorpVaultKV2Provider {
		vaultEngine, err := cryptoengines.NewVaultKV2Engine(logger, cfg)
		if err != nil {
			log.Warnf("skipping Hashicorp Vault KV2 engine with id %s. could not create Vault engine: %s", cfg.ID, err)
		} else {
			engines[cfg.ID] = &services.Engine{
				Default: cfg.ID == conf.CryptoEngines.DefaultEngine,
				Service: vaultEngine,
			}
		}
	}

	for _, cfg := range conf.CryptoEngines.AWSKMSProvider {
		awsCfg, err := config.GetAwsSdkConfig(cfg.AWSSDKConfig)
		if err != nil {
			log.Warnf("skipping AWS KMS engine with id %s: %s", cfg.ID, err)
			continue
		}

		awsEngine, err := cryptoengines.NewAWSKMSEngine(logger, *awsCfg, cfg.Metadata)
		if err != nil {
			log.Warnf("skipping AWS KMS engine with id %s. could not create KMS engine: %s", cfg.ID, err)
			continue
		} else {
			engines[cfg.ID] = &services.Engine{
				Default: cfg.ID == conf.CryptoEngines.DefaultEngine,
				Service: awsEngine,
			}
		}
	}

	for _, cfg := range conf.CryptoEngines.AWSSecretsManagerProvider {
		awsCfg, err := config.GetAwsSdkConfig(cfg.AWSSDKConfig)
		if err != nil {
			log.Warnf("skipping AWS Secrets Manager engine with id %s: %s", cfg.ID, err)
			continue
		}

		awsEngine, err := cryptoengines.NewAWSSecretManagerEngine(logger, *awsCfg, cfg.Metadata)
		if err != nil {
			log.Warnf("skipping AWS Secrets Manager with id %s. could not create Secrets Manager engine: %s", cfg.ID, err)
			continue
		} else {
			engines[cfg.ID] = &services.Engine{
				Default: cfg.ID == conf.CryptoEngines.DefaultEngine,
				Service: awsEngine,
			}
		}
	}

	for _, cfg := range conf.CryptoEngines.GolangProvider {
		engine := cryptoengines.NewGolangPEMEngine(logger, cfg)
		engines[cfg.ID] = &services.Engine{
			Default: cfg.ID == conf.CryptoEngines.DefaultEngine,
			Service: engine,
		}
	}

	for _, cfg := range conf.CryptoEngines.PKCS11Provider {
		engine, err := cryptoengines.NewPKCS11Engine(logger, cfg)
		if err != nil {
			log.Warnf("skipping PKCS11 provider with id %s. could not create PKCS11 engine: %s", cfg.ID, err)
		} else {
			engines[cfg.ID] = &services.Engine{
				Default: cfg.ID == conf.CryptoEngines.DefaultEngine,
				Service: engine,
			}
		}
	}

	return engines, nil
}
