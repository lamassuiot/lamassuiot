package main

import (
	"fmt"

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

	engine, err := createCryptoEngine(*conf)
	if err != nil {
		log.Fatal(err)
	}

	couchdbClient, err := couchdb.CreateCouchDBConnection(conf.Storage.CouchDB.HTTPConnection, conf.Storage.CouchDB.Username, conf.Storage.CouchDB.Password)
	if err != nil {
		log.Fatal(err)
	}

	caStorage, err := couchdb.NewCouchCARepository(couchdbClient)
	if err != nil {
		log.Fatal(err)
	}

	certStorage, err := couchdb.NewCouchCertificateRepository(couchdbClient)
	if err != nil {
		log.Fatal(err)
	}

	svc := services.NeCAService(services.CAServiceBuilder{
		CryptoEngine:         engine,
		CAStorage:            caStorage,
		CertificateStorage:   certStorage,
		CryptoMonitoringConf: conf.CryptoMonitoring,
	})
	caSvc := svc.(*services.CAServiceImpl)

	if conf.AMQPEventPublisher.Enabled {
		amqpHander, err := amqppub.SetupAMQPConnection(conf.AMQPEventPublisher)
		if err != nil {
			log.Fatal(err)
		}

		svc = amqppub.NewCAAmqpEventPublisher(amqpHander.PublisherChan)(svc)
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

func createCryptoEngine(conf config.CAConfig) (cryptoengines.CryptoEngine, error) {
	switch conf.CryptoEngine {
	case models.AWSKMS:
		awsKmsConfig := conf.AWSKMSProvider
		awsEngine, err := cryptoengines.NewAWSKMSEngine(awsKmsConfig.AccessKeyID, awsKmsConfig.SecretAccessKey, awsKmsConfig.Region)
		if err != nil {
			log.Panicf("could not create AWS KMS engine. Skipping engine: %s", err)
		}

		return awsEngine, nil
	case models.AWSSecretsManager:
		awsSecretsMngrCfg := conf.AWSSecretsManagerProvider
		awsEngine, err := cryptoengines.NewAWSSecretManagerEngine(awsSecretsMngrCfg.AccessKeyID, awsSecretsMngrCfg.SecretAccessKey, awsSecretsMngrCfg.Region)
		if err != nil {
			log.Panicf("could not create AWS Secrets Manager engine. Skipping engine: %s", err)
		}

		return awsEngine, nil
	case models.VaultKV2:
		vaultCryptoEngineConfig := conf.HashicorpVaultProvider
		vaultEngine, err := cryptoengines.NewVaultCryptoEngine(vaultCryptoEngineConfig)
		if err != nil {
			log.Panicf("could not create Vault engine. Skipping engine: %s", err)
		}

		return vaultEngine, nil
	case models.Golang:
		gopemConfig := conf.GoPemProvider
		gopemEngine, err := cryptoengines.NewGolangPEMEngine(gopemConfig.StorageDirectory)
		if err != nil {
			log.Panicf("could not create GoPEM engine. Skipping engine: %s", err)
		}

		return gopemEngine, nil
	}

	return nil, fmt.Errorf("no crypto engine")
}
