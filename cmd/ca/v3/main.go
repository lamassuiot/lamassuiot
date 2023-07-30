package main

import (
	"fmt"
	"io"

	formatter "github.com/antonfisher/nested-logrus-formatter"
	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/cryptoengines"
	"github.com/lamassuiot/lamassuiot/pkg/v3/middlewares/amqppub"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/routes"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
	"github.com/lamassuiot/lamassuiot/pkg/v3/storage"
	"github.com/lamassuiot/lamassuiot/pkg/v3/storage/couchdb"
	"github.com/lamassuiot/lamassuiot/pkg/v3/storage/postgres"
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

	conf, err := config.LoadConfig[config.CAConfig]()
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

	lCryprtoEng := configureLogger(globalLogLevel, conf.Logs.SubystemLogging.CryotoEngine, "CryptoEngine")
	lSvc := configureLogger(globalLogLevel, conf.Logs.SubystemLogging.Service, "Service")
	lHttp := configureLogger(globalLogLevel, conf.Logs.SubystemLogging.HttpTransport, "HTTP Server")
	lMessage := configureLogger(globalLogLevel, conf.Logs.SubystemLogging.MessagingEngine, "Messaging")
	lStorage := configureLogger(globalLogLevel, conf.Logs.SubystemLogging.StorageEngine, "Storage")

	engines, err := createCryptoEngines(lCryprtoEng, *conf)
	if err != nil {
		log.Fatal(err)
	}

	for engineID, engine := range engines {
		logEntry := log.NewEntry(log.StandardLogger())
		if engine.Default {
			logEntry = log.WithField("subsystem-provider", "DEFAULT ENGINE")

		}
		logEntry.Infof("loaded %s engine with id %s", engine.Service.GetEngineConfig().Type, engineID)
	}

	caStorage, certStorage, err := createStorageInstance(lStorage, conf.Storage)
	if err != nil {
		log.Fatal(err)
	}

	svc, err := services.NeCAService(services.CAServiceBuilder{
		Logger:               lSvc,
		CryptoEngines:        engines,
		CAStorage:            caStorage,
		CertificateStorage:   certStorage,
		CryptoMonitoringConf: conf.CryptoMonitoring,
	})
	if err != nil {
		log.Panicf("could not create CA service: %v", err)
	}

	caSvc := svc.(*services.CAServiceImpl)

	if conf.AMQPEventPublisher.Enabled {
		amqpHander, err := amqppub.SetupAMQPConnection(lMessage, conf.AMQPEventPublisher)
		if err != nil {
			log.Fatal(err)
		}

		svc = amqppub.NewCAAmqpEventPublisher(amqpHander.PublisherChan)(svc)
	}

	//this utilizes the middlewares from within the CA service (if svc.Service.func is uses instead of regular svc.func)
	caSvc.SetService(svc)

	err = routes.NewCAHTTPLayer(lHttp, svc, conf.Server, models.APIServiceInfo{
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

func createStorageInstance(logger *log.Entry, conf config.PluggableStorageEngine) (storage.CACertificatesRepo, storage.CertificatesRepo, error) {
	switch conf.Provider {
	case config.Postgres:
		psqlCli, err := postgres.CreatePostgresDBConnection(logger, conf.Postgres, "ca")
		if err != nil {
			log.Panicf("could not create postgres client: %s", err)
		}

		caStore, err := postgres.NewCAPostgresRepository(psqlCli)
		if err != nil {
			log.Panicf("could not initialize postgres ca client: %s", err)
		}

		certStore, err := postgres.NewCertificateRepository(psqlCli)
		if err != nil {
			log.Panicf("could not initialize postgres cert client: %s", err)
		}

		return caStore, certStore, nil
	case config.CouchDB:
		couchdbClient, err := couchdb.CreateCouchDBConnection(logger, conf.CouchDB)
		if err != nil {
			log.Panicf("could not create couchdb client: %s", err)
		}

		caStore, err := couchdb.NewCouchCARepository(couchdbClient)
		if err != nil {
			log.Panicf("could not initialize couchdb ca client: %s", err)
		}

		certStore, err := couchdb.NewCouchCertificateRepository(couchdbClient)
		if err != nil {
			log.Panicf("could not initialize couchdb cert client: %s", err)
		}

		return caStore, certStore, nil
	}

	return nil, nil, fmt.Errorf("no storage engine")
}

func createCryptoEngines(logger *log.Entry, conf config.CAConfig) (map[string]*services.Engine, error) {
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
		awsEngine, err := cryptoengines.NewAWSKMSEngine(logger, cfg)
		if err != nil {
			log.Warnf("skipping AWS KMS engine with id %s. could not create Vault engine: %s", cfg.ID, err)
		} else {
			engines[cfg.ID] = &services.Engine{
				Default: cfg.ID == conf.CryptoEngines.DefaultEngine,
				Service: awsEngine,
			}
		}
	}

	for _, cfg := range conf.CryptoEngines.AWSSecretsManagerProvider {
		awsEngine, err := cryptoengines.NewAWSSecretManagerEngine(logger, cfg)
		if err != nil {
			log.Warnf("skipping AWS KMS Secrets Manager with id %s. could not create Vault engine: %s", cfg.ID, err)
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

func configureLogger(defaultLevel log.Level, currentLevel config.LogLevel, subsystem string) *log.Entry {
	var err error
	logger := log.New()
	logger.SetFormatter(logFormatter)
	lSubystem := logger.WithField("subsystem", subsystem)

	if currentLevel == config.None {
		lSubystem.Infof("subsystem logging will be disabled")
		lSubystem.Logger.SetOutput(io.Discard)
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

		lSubystem.Logger.SetLevel(level)
	}
	lSubystem.Infof("log level set to '%s'", lSubystem.Logger.GetLevel())
	return lSubystem
}
