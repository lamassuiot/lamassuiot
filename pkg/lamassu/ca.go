package lamassu

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/cryptoengines"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/messaging"
	"github.com/lamassuiot/lamassuiot/pkg/v3/middlewares/amqppub"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/routes"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
	"github.com/lamassuiot/lamassuiot/pkg/v3/storage"
	"github.com/lamassuiot/lamassuiot/pkg/v3/storage/couchdb"
	"github.com/lamassuiot/lamassuiot/pkg/v3/storage/postgres"
	"github.com/lamassuiot/lamassuiot/pkg/v3/x509engines"
	log "github.com/sirupsen/logrus"
)

func AssembleCAServiceWithHTTPServer(conf config.CAConfig, serviceInfo models.APIServiceInfo) (*services.CAService, int, error) {
	caService, err := AssembleCAService(conf)
	if err != nil {
		return nil, -1, fmt.Errorf("could not assemble CA Service. Exiting: %s", err)
	}

	lHttp := helpers.ConfigureLogger(conf.Server.LogLevel, "HTTP Server")

	httpEngine := routes.NewGinEngine(lHttp)
	httpGrp := httpEngine.Group("/")
	routes.NewCAHTTPLayer(httpGrp, *caService)
	port, err := routes.RunHttpRouter(lHttp, httpEngine, conf.Server, serviceInfo)
	if err != nil {
		return nil, -1, fmt.Errorf("could not run CA Service http server: %s", err)
	}

	return caService, port, nil
}

func AssembleCAService(conf config.CAConfig) (*services.CAService, error) {
	lSvc := helpers.ConfigureLogger(conf.Logs.Level, "Service")
	lMessage := helpers.ConfigureLogger(conf.AMQPConnection.LogLevel, "Messaging")
	lStorage := helpers.ConfigureLogger(conf.Storage.LogLevel, "Storage")
	lCryptoEng := helpers.ConfigureLogger(conf.CryptoEngines.LogLevel, "CryptoEngine")

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

	caStorage, certStorage, err := createCAStorageInstance(lStorage, conf.Storage)
	if err != nil {
		return nil, fmt.Errorf("could not create CA storage instance: %s", err)
	}

	svc, err := services.NewCAService(services.CAServiceBuilder{
		Logger:               lSvc,
		CryptoEngines:        engines,
		CAStorage:            caStorage,
		CertificateStorage:   certStorage,
		CryptoMonitoringConf: conf.CryptoMonitoring,
	})
	if err != nil {
		return nil, fmt.Errorf("could not create CA service: %v", err)
	}

	caSvc := svc.(*services.CAServiceImpl)

	if conf.AMQPConnection.Enabled {
		log.Infof("AMQP event publisher enabled")
		amqpEventPub, err := messaging.SetupAMQPConnection(lMessage, conf.AMQPConnection)
		if err != nil {
			return nil, fmt.Errorf("could not setup AMQP connection: %s", err)
		}

		svc = amqppub.NewCAAmqpEventPublisher(amqpEventPub)(svc)
	}

	//this utilizes the middlewares from within the CA service (if svc.Service.func is uses instead of regular svc.func)
	caSvc.SetService(svc)

	return &svc, nil
}

func createCAStorageInstance(logger *log.Entry, conf config.PluggableStorageEngine) (storage.CACertificatesRepo, storage.CertificatesRepo, error) {
	switch conf.Provider {
	case config.Postgres:
		psqlCli, err := postgres.CreatePostgresDBConnection(logger, conf.Postgres, "ca")
		if err != nil {
			return nil, nil, fmt.Errorf("could not create postgres client: %s", err)
		}

		caStore, err := postgres.NewCAPostgresRepository(psqlCli)
		if err != nil {
			return nil, nil, fmt.Errorf("could not initialize postgres CA client: %s", err)
		}

		certStore, err := postgres.NewCertificateRepository(psqlCli)
		if err != nil {
			return nil, nil, fmt.Errorf("could not initialize postgres Cert client: %s", err)
		}

		return caStore, certStore, nil
	case config.CouchDB:
		couchdbClient, err := couchdb.CreateCouchDBConnection(logger, conf.CouchDB)
		if err != nil {
			return nil, nil, fmt.Errorf("could not create couchdb client: %s", err)
		}

		caStore, err := couchdb.NewCouchCARepository(couchdbClient)
		if err != nil {
			return nil, nil, fmt.Errorf("could not initialize couchdb CA client: %s", err)
		}

		certStore, err := couchdb.NewCouchCertificateRepository(couchdbClient)
		if err != nil {
			return nil, nil, fmt.Errorf("could not initialize couchdb Cert client: %s", err)
		}

		return caStore, certStore, nil
	}

	return nil, nil, fmt.Errorf("no storage engine")
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
