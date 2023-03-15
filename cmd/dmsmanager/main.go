package main

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"

	"github.com/lamassuiot/lamassuiot/pkg/clients"
	"github.com/lamassuiot/lamassuiot/pkg/config"
	"github.com/lamassuiot/lamassuiot/pkg/helppers"
	"github.com/lamassuiot/lamassuiot/pkg/middlewares/amqppub"
	"github.com/lamassuiot/lamassuiot/pkg/routes"
	"github.com/lamassuiot/lamassuiot/pkg/services"
	"github.com/lamassuiot/lamassuiot/pkg/storage/couchdb"
	log "github.com/sirupsen/logrus"
)

func main() {
	conf, err := config.LoadConfig[config.DMSconfig]()
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

	dmsStorage, err := couchdb.NewCouchDMSRepository(url.URL{
		Scheme: string(conf.Storage.CouchDB.Protocol),
		Host:   fmt.Sprintf("%s:%d", conf.Storage.CouchDB.Hostname, conf.Storage.CouchDB.Port),
	}, conf.Storage.CouchDB.Username, conf.Storage.CouchDB.Password)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(amqpPub)

	caURL := fmt.Sprintf("%s://%s:%d", conf.CAClient.Protocol, conf.CAClient.Hostname, conf.CAClient.Port)
	client := clients.NewCAClient(*http.DefaultClient, caURL)

	var downstreamCert *x509.Certificate
	if conf.Server.Protocol == config.HTTPS {
		downstreamCert, err = helppers.ReadCertificateFromFile(conf.DownstreamCertificateFile)
		if err != nil {
			log.Fatal(err)
		}
	}

	svc := services.NewDMSManagerService(services.ServiceDMSBuilder{
		CAClient:       client,
		DMSStorage:     dmsStorage,
		DownstreamCert: downstreamCert,
	})

	err = routes.NewDMSManagerHTTPLayer(svc, conf.Server.ListenAddress, conf.Server.Port, conf.Server.DebugMode)
	if err != nil {
		log.Fatal(err)
	}

	forever := make(chan struct{})
	<-forever
}
