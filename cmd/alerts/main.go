package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/lamassuiot/lamassuiot/pkg/alerts/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/alerts/server/api/service/outputchannels"
	"github.com/lamassuiot/lamassuiot/pkg/alerts/server/api/transport"
	"github.com/lamassuiot/lamassuiot/pkg/alerts/server/config"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server"
	"github.com/opentracing/opentracing-go"
	"github.com/uptrace/opentelemetry-go-extra/otelgorm"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"

	postgresRepository "github.com/lamassuiot/lamassuiot/pkg/alerts/server/api/repository/postgres"
)

func main() {
	config := config.NewMailConfig()
	mainServer := server.NewServer(config)

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable", config.PostgresHostname, config.PostgresUser, config.PostgresPassword, config.PostgresDatabase, config.PostgresPort)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: gormLogger.Default.LogMode(gormLogger.Silent),
	})
	if err != nil {
		level.Error(mainServer.Logger).Log("msg", "Could not connect to Postgres", "err", err)
		os.Exit(1)
	}

	if err := db.Use(otelgorm.NewPlugin()); err != nil {
		level.Error(mainServer.Logger).Log("msg", "Could not initialize OpenTelemetry DB-GORM plugin", "err", err)
		os.Exit(1)
	}

	mailRepo := postgresRepository.NewPostgresDB(db, mainServer.Logger)

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
	var s service.Service
	s, err = service.NewAlertsService(mainServer.Logger, mailRepo, config.TemplateJSON, smtpConfig)
	if err != nil {
		level.Error(mainServer.Logger).Log("msg", "Could not create mail service", "err", err)
		os.Exit(1)
	}

	mainServer.AddHttpHandler("/v1/", http.StripPrefix("/v1", transport.MakeHTTPHandler(s, log.With(mainServer.Logger, "component", "HTTPS"), opentracing.GlobalTracer())))
	mainServer.AddAmqpConsumer(config.ServiceName, []string{"#"}, transport.MakeAmqpHandler(s, mainServer.Logger, opentracing.GlobalTracer()))

	errs := make(chan error)
	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errs <- fmt.Errorf("%s", <-c)
	}()

	mainServer.Run(errs)
	level.Info(mainServer.Logger).Log("exit", <-errs)
}
