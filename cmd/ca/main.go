package main

import (
	"github.com/lamassuiot/lamassuiot/internal/ca/cryptoengines"
	"github.com/lamassuiot/lamassuiot/pkg/config"
	"github.com/lamassuiot/lamassuiot/pkg/middlewares/amqppub"
	"github.com/lamassuiot/lamassuiot/pkg/models"
	"github.com/lamassuiot/lamassuiot/pkg/routes"
	"github.com/lamassuiot/lamassuiot/pkg/services"
	"github.com/lamassuiot/lamassuiot/pkg/storage/couchdb"
	log "github.com/sirupsen/logrus"
)

var (
	version   string = "v0"    // api version
	sha1ver   string = "-"     // sha1 revision used to build the program
	buildTime string = "devTS" // when the executable was built
)

func main() {
	customFormatter := new(log.TextFormatter)
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	customFormatter.FullTimestamp = true
	log.SetFormatter(customFormatter)

	log.Infof("starting api: version=%s buildTime=%s sha1ver=%s", version, buildTime, sha1ver)

	conf, err := config.LoadConfig[config.CAConfig]()
	if err != nil {
		log.Fatal(err)
	}

	logLevel, err := log.ParseLevel(string(conf.Logs.Level))
	if err != nil {
		log.SetLevel(log.InfoLevel)
		log.Warn("unknown log level. defaulting to 'info' log level")
	} else {
		log.SetLevel(logLevel)
	}

	engines := createCryptoEngines(*conf)

	caStorage, err := couchdb.NewCouchCARepository(conf.Storage.CouchDB.HTTPConnection, conf.Storage.CouchDB.Username, conf.Storage.CouchDB.Password)
	if err != nil {
		log.Fatal(err)
	}

	certStorage, err := couchdb.NewCouchCertificateRepository(conf.Storage.CouchDB.HTTPConnection, conf.Storage.CouchDB.Username, conf.Storage.CouchDB.Password)
	if err != nil {
		log.Fatal(err)
	}

	svc := services.NeCAService(services.CAServiceBuilder{
		CryptoEngines:        engines,
		CAStorage:            caStorage,
		CertificateStorage:   certStorage,
		CryptoMonitoringConf: conf.CryptoMonitoring,
	})
	caSvc := svc.(*services.CAServiceImpl)

	if conf.AMQPEventPublisher.Enabled {
		_, amqpPub, err := amqppub.SetupAMQPConnection(conf.AMQPEventPublisher)
		if err != nil {
			log.Fatal(err)
		}

		svc = amqppub.NewCAAmqpEventPublisher(amqpPub)(svc)
	}

	//this utilizes the middlewares from within the CA service (if svc.Service.func is uses instead of regular svc.func)
	caSvc.SetService(svc)

	err = routes.NewCAHTTPLayer(svc, conf.Server, models.APIServiceInfo{
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

func createCryptoEngines(conf config.CAConfig) map[string]services.EngineServiceMap {
	engines := map[string]services.EngineServiceMap{}

	//Create all Vault CryptoEngines
	for _, vaultCryptoEngineConfig := range conf.CryptoEngines.HashicorpVaultProviders {
		vaultEngine, err := cryptoengines.NewVaultCryptoEngine(vaultCryptoEngineConfig)
		if err != nil {
			log.Warnf("could not create Vault engine. Skipping engine: %s", err)
			continue
		}

		log.Infof("adding new Vault engine with ID: %s", vaultCryptoEngineConfig.ID)
		engines[vaultCryptoEngineConfig.ID] = services.EngineServiceMap{
			Name:         vaultCryptoEngineConfig.Name,
			Metadata:     vaultCryptoEngineConfig.Metadata,
			CryptoEngine: vaultEngine,
		}
	}

	//Create all GoPEM CryptoEngines
	for _, gopemConfig := range conf.CryptoEngines.GoPemProviders {
		gopemEngine, err := cryptoengines.NewGolangPEMEngine(gopemConfig.StorageDirectory)
		if err != nil {
			log.Warnf("could not create GoPEM engine. Skipping engine: %s", err)
			continue
		}

		log.Infof("adding new GoPEM engine with ID: %s", gopemConfig.ID)
		engines[gopemConfig.ID] = services.EngineServiceMap{
			Name:         gopemConfig.Name,
			Metadata:     gopemConfig.Metadata,
			CryptoEngine: gopemEngine,
		}
	}

	//Create all AWSKMS CryptoEngines
	for _, awsKmsConfig := range conf.CryptoEngines.AWSKMSProviders {
		awsEngine, err := cryptoengines.NewAWSKMSEngine(awsKmsConfig.AccessKeyID, awsKmsConfig.SecretAccessKey, awsKmsConfig.Region)
		if err != nil {
			log.Warnf("could not create AWS KMS engine. Skipping engine: %s", err)
			continue
		}

		log.Infof("adding new AWS KMS engine with ID: %s", awsKmsConfig.ID)
		engines[awsKmsConfig.ID] = services.EngineServiceMap{
			Name:         awsKmsConfig.Name,
			Metadata:     awsKmsConfig.Metadata,
			CryptoEngine: awsEngine,
		}

	}

	//Create all AWS Secret Manager CryptoEngines
	for _, awsSecretsMngrCfg := range conf.CryptoEngines.AWSSecretsManagerProviders {
		awsEngine, err := cryptoengines.NewAWSSecretManagerEngine(awsSecretsMngrCfg.AccessKeyID, awsSecretsMngrCfg.SecretAccessKey, awsSecretsMngrCfg.Region)
		if err != nil {
			log.Warnf("could not create AWS Secrets Manager engine. Skipping engine: %s", err)
			continue
		}

		log.Infof("adding new AWS Secrets Manager engine with ID: %s", awsSecretsMngrCfg.ID)
		engines[awsSecretsMngrCfg.ID] = services.EngineServiceMap{
			Name:         awsSecretsMngrCfg.Name,
			Metadata:     awsSecretsMngrCfg.Metadata,
			CryptoEngine: awsEngine,
		}

	}

	return engines
}
