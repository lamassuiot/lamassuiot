package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	lamassucaclient "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/transport"
	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/config"
	clientUtils "github.com/lamassuiot/lamassuiot/pkg/utils/client"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server"
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

	dsn := fmt.Sprintf("host=%svc user=%svc password=%svc dbname=%svc port=%svc sslmode=disable", config.PostgresHostname, config.PostgresUsername, config.PostgresPassword, config.PostgresDatabase, config.PostgresPort)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: dbLogrus,
	})
	if err != nil {
		log.Fatal(err)
	}

	dmsRepo := postgresRepository.NewPostgresDB(db)

	var caClient lamassucaclient.LamassuCAClient
	parsedLamassuCAURL, err := url.Parse(config.LamassuCAAddress)
	if err != nil {
		log.Fatal("Could not parse CA URL: ", err)
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

	svc := service.NewDMSManagerService(dmsRepo, &caClient)
	dmsSvc := svc.(*service.DMSManagerService)

	svc = service.LoggingMiddleware()(svc)
	svc = service.NewAMQPMiddleware(mainServer.AmqpPublisher)(svc)
	svc = service.NewInputValudationMiddleware()(svc)

	dmsSvc.SetService(svc)

	mainServer.AddHttpHandler("/v1/", http.StripPrefix("/v1", transport.MakeHTTPHandler(svc)))

	mainServer.Run()
	forever := make(chan struct{})
	<-forever
}
