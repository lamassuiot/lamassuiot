package main

import (
	"fmt"
	"net/http"

	"github.com/lamassuiot/lamassuiot/pkg/alerts/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/alerts/server/api/service/outputchannels"
	"github.com/lamassuiot/lamassuiot/pkg/alerts/server/api/transport"
	"github.com/lamassuiot/lamassuiot/pkg/alerts/server/config"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server"
	gorm_logrus "github.com/onrik/gorm-logrus"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"

	postgresRepository "github.com/lamassuiot/lamassuiot/pkg/alerts/server/api/repository/postgres"
)

func main() {
	config := config.NewMailConfig()

	dbLogrus := gormLogger.Default.LogMode(gormLogger.Silent)
	if config.DebugMode {
		logrus.SetLevel(logrus.InfoLevel)
		dbLogrus = gorm_logrus.New()
		dbLogrus.LogMode(gormLogger.Info)
	}

	mainServer := server.NewServer(config)

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable", config.PostgresHostname, config.PostgresUsername, config.PostgresPassword, config.PostgresDatabase, config.PostgresPort)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: gormLogger.Default.LogMode(gormLogger.Silent),
	})
	if err != nil {
		log.Fatal(err)
	}

	mailRepo := postgresRepository.NewPostgresDB(db)

	smtpConfig := outputchannels.SMTPOutputService{
		Host:              config.SMTPHost,
		Port:              config.SMTPPort,
		Username:          config.SMTPUsername,
		Password:          config.SMTPPassword,
		From:              config.SMTPFrom,
		SSL:               config.SMTPEnableSSL,
		Insecure:          config.SMTPInsecure,
		EmailTemplateFile: config.TemplateHTML,
	}

	var svc service.Service
	svc, err = service.NewAlertsService(mailRepo, config.TemplateJSON, smtpConfig)
	if err != nil {
		log.Fatal("Could not create mail service: ", err)
	}

	svc = service.NewInputValudationMiddleware()(svc)
	svc = service.LoggingMiddleware()(svc)

	mainServer.AddHttpHandler("/v1/", http.StripPrefix("/v1", transport.MakeHTTPHandler(svc)))
	mainServer.AddAmqpConsumer(config.ServiceName, []string{"#"}, transport.MakeAmqpHandler(svc))

}
