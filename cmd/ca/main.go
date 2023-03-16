package main

import (
	"crypto/x509"
	"fmt"
	"net/url"

	"github.com/lamassuiot/lamassuiot/internal/ca/cryptoengines"
	"github.com/lamassuiot/lamassuiot/pkg/config"
	"github.com/lamassuiot/lamassuiot/pkg/helppers"
	"github.com/lamassuiot/lamassuiot/pkg/middlewares/amqppub"
	"github.com/lamassuiot/lamassuiot/pkg/routes"
	"github.com/lamassuiot/lamassuiot/pkg/services"
	"github.com/lamassuiot/lamassuiot/pkg/storage/couchdb"
	log "github.com/sirupsen/logrus"
)

func main() {
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

	_, amqpPub, err := amqppub.SetupAMQPConnection(conf.AMQPEventPublisher)
	if err != nil {
		log.Fatal(err)
	}

	engines := createCryptoEngines(*conf)

	caStorage, err := couchdb.NewCouchCARepository(url.URL{
		Scheme: string(conf.Storage.CouchDB.Protocol),
		Host:   fmt.Sprintf("%s:%d", conf.Storage.CouchDB.Hostname, conf.Storage.CouchDB.Port),
	}, conf.Storage.CouchDB.Username, conf.Storage.CouchDB.Password)

	if err != nil {
		log.Fatal(err)
	}

	certStorage, err := couchdb.NewCouchCertificateRepository(url.URL{
		Scheme: string(conf.Storage.CouchDB.Protocol),
		Host:   fmt.Sprintf("%s:%d", conf.Storage.CouchDB.Hostname, conf.Storage.CouchDB.Port),
	}, conf.Storage.CouchDB.Username, conf.Storage.CouchDB.Password)

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

	svc = amqppub.NewCAAmqpEventPublisher(amqpPub)(svc)

	//this utilizes the middlewares from within the CA service (if svc.Service.func is uses instead of regular svc.func)
	caSvc.SetService(svc)

	err = routes.NewCAHTTPLayer(svc, conf.Server.ListenAddress, conf.Server.Port, conf.Server.DebugMode)
	if err != nil {
		log.Fatal(err)
	}

	forever := make(chan struct{})
	<-forever
}

func createCryptoEngines(conf config.CAConfig) map[string]services.EngineServiceMap {
	var err error

	engines := map[string]services.EngineServiceMap{}

	//Create all Vault CryptoEngines
	for _, vaultCryptoEngineConfig := range conf.CryptoEngines.HashicorpVaultProviders {
		var caCert *x509.Certificate
		if vaultCryptoEngineConfig.CACertificateFile != "" {
			caCert, err = helppers.ReadCertificateFromFile(vaultCryptoEngineConfig.CACertificateFile)
			if err != nil {
				log.Warnf("could not load CA certificate for Vault. Skipping engine: %s", err)
				continue
			}
		}

		addr := fmt.Sprintf("%s://%s:%d", vaultCryptoEngineConfig.Protocol, vaultCryptoEngineConfig.Hostname, vaultCryptoEngineConfig.Port)
		roleID := vaultCryptoEngineConfig.RoleID
		secretID := vaultCryptoEngineConfig.SecretID
		insecure := vaultCryptoEngineConfig.InsecureSkipVerify
		autoUnseal := vaultCryptoEngineConfig.AutoUnsealEnabled
		autoUnsealKeysFile := vaultCryptoEngineConfig.AutoUnsealKeysFile
		vaultEngine, err := cryptoengines.NewVaultCryptoEngine(addr, roleID, secretID, caCert, insecure, autoUnseal, autoUnsealKeysFile)

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

	return engines
}
