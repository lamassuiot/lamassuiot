package main

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
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

var (
	version   string = "v0"    // api version
	sha1ver   string = "-"     // sha1 revision used to build the program
	buildTime string = "devTS" // when the executable was built
)

func main() {
	log.SetFormatter(helpers.LogFormatter)
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

	confBytes, err := yaml.Marshal(conf)
	if err != nil {
		log.Fatalf("could not dump yaml config: %s", err)
	}
	log.Debugf("===================================================")
	log.Debugf("%s", confBytes)
	log.Debugf("===================================================")

	lCryptoEng := helpers.ConfigureLogger(globalLogLevel, conf.Logs.SubsystemLogging.CryptoEngine, "CryptoEngine")
	lSvc := helpers.ConfigureLogger(globalLogLevel, conf.Logs.SubsystemLogging.Service, "Service")
	lHttp := helpers.ConfigureLogger(globalLogLevel, conf.Logs.SubsystemLogging.HttpTransport, "HTTP Server")
	lMessage := helpers.ConfigureLogger(globalLogLevel, conf.Logs.SubsystemLogging.MessagingEngine, "Messaging")
	lStorage := helpers.ConfigureLogger(globalLogLevel, conf.Logs.SubsystemLogging.StorageEngine, "Storage")

	engines, err := createCryptoEngines(lCryptoEng, *conf)
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

	svc, err := services.NewCAService(services.CAServiceBuilder{
		Logger:               lSvc,
		CryptoEngines:        engines,
		CAStorage:            caStorage,
		CertificateStorage:   certStorage,
		CryptoMonitoringConf: conf.CryptoMonitoring,
	})
	if err != nil {
		log.Fatalf("could not create CA service: %v", err)
	}

	caSvc := svc.(*services.CAServiceImpl)

	if conf.AMQPConnection.Enabled {
		log.Infof("AMQP event publisher enabled")
		amqpEventPub, err := messaging.SetupAMQPConnection(lMessage, conf.AMQPConnection)
		if err != nil {
			log.Fatal(err)
		}

		svc = amqppub.NewCAAmqpEventPublisher(amqpEventPub)(svc)
	}

	//this utilizes the middlewares from within the CA service (if svc.Service.func is uses instead of regular svc.func)
	caSvc.SetService(svc)

	router := routes.NewCAHTTPLayer(lHttp, svc)
	routes.RunHttpRouter(lHttp, router, conf.Server, models.APIServiceInfo{
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
			log.Fatalf("could not create postgres client: %s", err)
		}

		caStore, err := postgres.NewCAPostgresRepository(psqlCli)
		if err != nil {
			log.Fatalf("could not initialize postgres CA client: %s", err)
		}

		certStore, err := postgres.NewCertificateRepository(psqlCli)
		if err != nil {
			log.Fatalf("could not initialize postgres Cert client: %s", err)
		}

		return caStore, certStore, nil
	case config.CouchDB:
		couchdbClient, err := couchdb.CreateCouchDBConnection(logger, conf.CouchDB)
		if err != nil {
			log.Fatalf("could not create couchdb client: %s", err)
		}

		caStore, err := couchdb.NewCouchCARepository(couchdbClient)
		if err != nil {
			log.Fatalf("could not initialize couchdb CA client: %s", err)
		}

		certStore, err := couchdb.NewCouchCertificateRepository(couchdbClient)
		if err != nil {
			log.Fatalf("could not initialize couchdb Cert client: %s", err)
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
