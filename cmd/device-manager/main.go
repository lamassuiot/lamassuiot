package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/lamassuiot/lamassuiot/pkg/v3/clients"
	lamassuSDK "github.com/lamassuiot/lamassuiot/pkg/v3/clients"
	configV3 "github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"

	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/transport"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/config"
	lamassudmsclient "github.com/lamassuiot/lamassuiot/pkg/dms-manager/client"
	esttransport "github.com/lamassuiot/lamassuiot/pkg/est/server/api/transport"
	clientUtils "github.com/lamassuiot/lamassuiot/pkg/utils/client"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server"
	gorm_logrus "github.com/onrik/gorm-logrus"
	log "github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"

	badgerRepository "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/repository/badger"
	postgresRepository "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/repository/postgres"
)

func main() {
	config := config.NewDeviceManagerConfig()

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

	statsRepo, err := badgerRepository.NewStatisticsDBInMemory()
	if err != nil {
		log.Fatal("Failed to connect to badger: ", err)
	}

	deviceRepo := postgresRepository.NewDevicesPostgresDB(db)
	logsRepo := postgresRepository.NewLogsPostgresDB(db)

	var lamassuCAClient lamassuSDK.CAClient

	lCAClient := helpers.ConfigureLogger(log.TraceLevel, configV3.Trace, "LMS SDK - CA Client")

	caHttpCli, err := clients.BuildHTTPClient(configV3.HTTPClient{}, lCAClient)
	if err != nil {
		log.Fatalf("could not build HTTP CA Client: %s", err)
	}
	lamassuCAClient = lamassuSDK.NewHttpCAClient(caHttpCli, config.LamassuCAAddress)
	if err != nil {
		log.Fatal("Could not create LamassuCA client: ", err)
	}

	var dmsClient lamassudmsclient.LamassuDMSManagerClient
	parsedLamassuDMSURL, err := url.Parse(config.LamassuDMSManagerAddress)
	if err != nil {
		log.Fatal("Could not parse LamassuDMS url: ", err)
	}

	if strings.HasPrefix(config.LamassuDMSManagerAddress, "https") {
		dmsClient, err = lamassudmsclient.NewLamassuDMSManagerClientConfig(clientUtils.BaseClientConfigurationuration{
			URL:        parsedLamassuDMSURL,
			AuthMethod: clientUtils.AuthMethodMutualTLS,
			AuthMethodConfig: &clientUtils.MutualTLSConfig{
				ClientCert: config.CertFile,
				ClientKey:  config.KeyFile,
			},
			CACertificate: config.LamassuDMSManagerCertFile,
		})
		if err != nil {
			log.Fatal("Could not create LamassuDMS client: ", err)
		}
	} else {
		dmsClient, err = lamassudmsclient.NewLamassuDMSManagerClientConfig(clientUtils.BaseClientConfigurationuration{
			URL:        parsedLamassuDMSURL,
			AuthMethod: clientUtils.AuthMethodNone,
		})
		if err != nil {
			log.Fatal("Could not create LamassuDMS client: ", err)
		}
	}

	upstreamCA, err := readCertificarteFille(config.CACertFile)
	if err != nil {
		log.Fatal("Could not read CA certificate: ", err)
	}

	svc := service.NewDeviceManagerService(upstreamCA, deviceRepo, logsRepo, statsRepo, config.MinimumReenrollDays, lamassuCAClient, dmsClient)
	dmSvc := svc.(*service.DevicesService)

	svc = service.LoggingMiddleware()(svc)
	svc = service.NewAMQPMiddleware(mainServer.AmqpPublisher)(svc)
	svc = service.NewInputValudationMiddleware()(svc)

	dmSvc.SetService(svc)

	mainServer.AddHttpHandler("/v1/", http.StripPrefix("/v1", transport.MakeHTTPHandler(svc)))
	mainServer.AddHttpHandler("/.well-known/", esttransport.MakeHTTPHandler(svc))

	mainServer.AddAmqpConsumer(config.ServiceName, []string{"io.lamassuiot.certificate.update", "io.lamassuiot.certificate.revoke"}, transport.MakeAmqpHandler(svc))

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
