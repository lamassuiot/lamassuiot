package main

import (
	"crypto/x509"
	"fmt"

	"github.com/lamassuiot/lamassuiot/pkg/clients"
	"github.com/lamassuiot/lamassuiot/pkg/config"
	"github.com/lamassuiot/lamassuiot/pkg/helpers"
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

	conf, err := config.LoadConfig[config.DeviceManagerConfig]()
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

	if conf.AMQPEventPublisher.Enabled {
		amqpHander, err := amqppub.SetupAMQPConnection(conf.AMQPEventPublisher)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println(amqpHander)
	}

	couchdbClient, err := couchdb.CreateCouchDBConnection(conf.Storage.CouchDB.HTTPConnection, conf.Storage.CouchDB.Username, conf.Storage.CouchDB.Password)
	if err != nil {
		log.Fatal(err)
	}

	devMngrStroage, err := couchdb.NewCouchDeviceManagerRepository(couchdbClient)
	if err != nil {
		log.Fatal(err)
	}

	caHttpClient, err := clients.BuildHTTPClient(conf.CAClient.HTTPClient, "CA")
	if err != nil {
		log.Fatal(err)
	}

	var upstreamCA *x509.Certificate
	if conf.Server.Authentication.MutualTLS.Enabled {
		upstreamCA, err = helpers.ReadCertificateFromFile(conf.Server.Authentication.MutualTLS.CACertificateFile)
		if err != nil {
			log.Fatal(err)
		}
	}

	caClient := clients.NewCAClient(caHttpClient, clients.BuildURL(conf.CAClient.HTTPClient))

	dmsHttpClient, err := clients.BuildHTTPClient(conf.DMSManagerClient.HTTPClient, "DMS Mngr")
	if err != nil {
		log.Fatal(err)
	}

	dmsClient := clients.NewDMSManagerClient(dmsHttpClient, clients.BuildURL(conf.DMSManagerClient.HTTPClient))

	svc := services.NewDeviceManagerService(services.ServiceDeviceManagerBuilder{
		CAClient:       caClient,
		DevicesStorage: devMngrStroage,
		DMSClient:      dmsClient,
		UpstreamCA:     upstreamCA,
	})

	err = routes.NewDeviceManagerHTTPLayer(svc, conf.Server, models.APIServiceInfo{
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
