package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	lamassudevmanager "github.com/lamassuiot/lamassuiot/pkg/device-manager/client"
	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/transport"
	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/config"
	esttransport "github.com/lamassuiot/lamassuiot/pkg/est/server/api/transport"
	clientUtils "github.com/lamassuiot/lamassuiot/pkg/utils/client"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server"
	lamassuSDK "github.com/lamassuiot/lamassuiot/pkg/v3/clients"
	gorm_logrus "github.com/onrik/gorm-logrus"
	log "github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"

	postgresRepository "github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/repository/postgres"
)

func main() {
	config := config.NewDMSManagerConfig()

	dbLogrus := gormLogger.Default.LogMode(gormLogger.Silent)
	if config.DebugMode {
		dbLogrus = gorm_logrus.New()
		dbLogrus.LogMode(gormLogger.Info)
	}

	mainServer := server.NewServer(config)

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable", config.PostgresHostname, config.PostgresUsername, config.PostgresPassword, config.PostgresDatabase, config.PostgresPort)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: dbLogrus,
	})
	if err != nil {
		log.Fatal(err)
	}

	dmsRepo := postgresRepository.NewPostgresDB(db)

	var lamassuCAClient lamassuSDK.CAClient
	lamassuCAClient = lamassuSDK.NewHttpCAClient(http.DefaultClient, config.LamassuCAAddress)
	if err != nil {
		log.Fatal("Could not create LamassuCA client: ", err)
	}

	var devManagerClient lamassudevmanager.LamassuDeviceManagerClient
	parsedLamassuDevManagerURL, err := url.Parse(config.LamassuDeviceManagerAddress)
	if err != nil {
		log.Fatal("Could not parse Device Manager URL: ", err)
	}

	if strings.HasPrefix(config.LamassuDeviceManagerAddress, "https") {
		devManagerClient, err = lamassudevmanager.NewLamassuDeviceManagerClient(clientUtils.BaseClientConfigurationuration{
			URL:        parsedLamassuDevManagerURL,
			AuthMethod: clientUtils.AuthMethodMutualTLS,
			AuthMethodConfig: &clientUtils.MutualTLSConfig{
				ClientCert: config.CertFile,
				ClientKey:  config.KeyFile,
			},
			CACertificate: config.LamassuDeviceManagerCertFile,
		})
		if err != nil {
			log.Fatal("Could not create Device Manager client: ", err)
		}
	} else {
		devManagerClient, err = lamassudevmanager.NewLamassuDeviceManagerClient(clientUtils.BaseClientConfigurationuration{
			URL:        parsedLamassuDevManagerURL,
			AuthMethod: clientUtils.AuthMethodNone,
		})
		if err != nil {
			log.Fatal("Could not create Device Manager client: ", err)
		}
	}

	caCert, err := readCertificarteFille(config.DownstreamCACert)
	if err != nil {
		log.Fatal("Could not parse downsrteam CA certificate: ", err)
	}

	upstreamCert, err := readCertificarteFille(config.CertFile)
	if err != nil {
		log.Fatal("Could not parse upstream certificate: ", err)
	}

	key, _ := ioutil.ReadFile(config.KeyFile)
	var upstreamKey interface{}
	block, _ := pem.Decode([]byte(key))
	upstreamKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		upstreamKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			upstreamKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				log.Fatal("Could not parse upstream Key: ", err)
			}
		}
	}

	svc := service.NewDMSManagerService(dmsRepo, lamassuCAClient, &devManagerClient, caCert, upstreamCert, upstreamKey, config.LamassuDeviceManagerAddress)
	dmsSvc := svc.(*service.DMSManagerService)

	svc = service.LoggingMiddleware()(svc)
	svc = service.NewAMQPMiddleware(mainServer.AmqpPublisher)(svc)
	svc = service.NewInputValudationMiddleware()(svc)

	dmsSvc.SetService(svc)

	mainServer.AddHttpHandler("/v1/", http.StripPrefix("/v1", transport.MakeHTTPHandler(svc)))
	mainServer.AddHttpHandler("/.well-known/", esttransport.MakeHTTPHandler(svc))

	mainServer.Run()
	forever := make(chan struct{})
	<-forever
}

func readCertificarteFille(path string) (*x509.Certificate, error) {
	certContent, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cpb, _ := pem.Decode(certContent)

	cert, err := x509.ParseCertificate(cpb.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}
