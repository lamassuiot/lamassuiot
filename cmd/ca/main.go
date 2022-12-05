package main

import (
	"fmt"
	"net/http"

	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service"
	cryptoengines "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service/crypto-engines"
	x509engines "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service/x509-engines"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/transport"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/config"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server"
	gorm_logrus "github.com/onrik/gorm-logrus"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"

	postgresRepository "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/repository/postgres"
)

func main() {
	config := config.NewCAConfig()

	dbLogrus := gormLogger.Default.LogMode(gormLogger.Silent)
	if config.DebugMode {
		logrus.SetLevel(logrus.InfoLevel)
		dbLogrus = gorm_logrus.New()
		dbLogrus.LogMode(gormLogger.Info)
	}

	mainServer := server.NewServer(config)

	var engine x509engines.X509Engine

	var svc service.Service

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable", config.PostgresHostname, config.PostgresUsername, config.PostgresPassword, config.PostgresDatabase, config.PostgresPort)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: dbLogrus,
	})
	if err != nil {
		log.Fatal(err)
	}

	certificateRepository := postgresRepository.NewPostgresDB(db)

	switch config.Engine {
	case "gopem":
		gopemEngine, err := cryptoengines.NewGolangPEMEngine(config.GopemData)
		if err != nil {
			log.Fatal("Could not initialize Golang PEM engine: ", err)
		}

		engine = x509engines.NewStandardx509Engine(gopemEngine, config.OcspUrl)

	case "vault":
		engine, err = x509engines.NewVaultx509Engine(config.VaultAddress, config.VaultPkiCaPath, config.VaultRoleID, config.VaultSecretID, config.VaultCA, config.VaultUnsealKeysFile, config.OcspUrl)
		if err != nil {
			log.Fatal("Could not start connection with Vault Secret Engine: ", err)
		}

	default:
		log.Fatal("Engine not supported")
	}

	svc = service.NewCAService(engine, certificateRepository, config.OcspUrl, config.AboutToExpireDays)

	log.Info("Engine initialized")
	log.Info(fmt.Sprintf("Engine options: %v", svc.GetEngineProviderInfo()))

	svcProvider := service.NewServiceProvider(svc, &mainServer.AmqpPublisher)

	mainServer.AddHttpHandler("/v1/", http.StripPrefix("/v1", transport.MakeHTTPHandler(svcProvider)))

	mainServer.Run()
	forever := make(chan struct{})
	<-forever
}
