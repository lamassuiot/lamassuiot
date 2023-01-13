package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	lamassucaclient "github.com/lamassuiot/lamassuiot/pkg/ca/client"
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

	var caClient lamassucaclient.LamassuCAClient
	parsedLamassuCAURL, err := url.Parse(config.LamassuCAAddress)
	if err != nil {
		log.Fatal("Could not parse CA URL")
		os.Exit(1)
	}

	if strings.HasPrefix(config.LamassuCAAddress, "https") {
		caClient, err = lamassucaclient.NewLamassuCAClient(clientUtils.BaseClientConfigurationuration{
			URL:        parsedLamassuCAURL,
			AuthMethod: clientUtils.AuthMethodMutualTLS,
			AuthMethodConfig: &clientUtils.MutualTLSConfig{
				ClientCert: config.CertFile,
				ClientKey:  config.KeyFile,
			},
			CACertificate: config.LamassuCACertFile,
		})
		if err != nil {
			log.Fatal("Could not create LamassuCA client: ", err)
		}
	} else {
		caClient, err = lamassucaclient.NewLamassuCAClient(clientUtils.BaseClientConfigurationuration{
			URL:        parsedLamassuCAURL,
			AuthMethod: clientUtils.AuthMethodNone,
		})
		if err != nil {
			log.Fatal("Could not create LamassuCA client: ", err)
		}
	}

	var dmsClient lamassudmsclient.LamassuDMSManagerClient
	parsedLamassuDMSURL, err := url.Parse(config.LamassuDMSManagerAddress)
	if err != nil {
		log.Fatal("Could not parse LamassuDMS url: ", err)
	}

	if strings.HasPrefix(config.LamassuCAAddress, "https") {
		dmsClient, err = lamassudmsclient.NewLamassuDMSManagerClientConfig(clientUtils.BaseClientConfigurationuration{
			URL:        parsedLamassuDMSURL,
			AuthMethod: clientUtils.AuthMethodMutualTLS,
			AuthMethodConfig: &clientUtils.MutualTLSConfig{
				ClientCert: config.CertFile,
				ClientKey:  config.KeyFile,
			},
			CACertificate: config.LamassuCACertFile,
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

	svc := service.NewDeviceManagerService(deviceRepo, logsRepo, statsRepo, config.MinimumReenrollDays, caClient, dmsClient)
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
