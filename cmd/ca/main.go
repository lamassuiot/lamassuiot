package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/transport"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/config"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server"
	"github.com/opentracing/opentracing-go"
	"github.com/uptrace/opentelemetry-go-extra/otelgorm"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"

	postgresRepository "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/repository/postgres"
)

func main() {
	config := config.NewCAConfig()
	mainServer := server.NewServer(config)

	/*var engine service.CryptoEngine
	switch config.Engine {
	case "pkcs11":
		hsmEngine, err := cryptoengines.NewHSMPEngine(mainServer.Logger, config.Pkcs11Driver, config.Pkcs11Label, config.Pkcs11Pin)
		if err != nil {
			level.Error(mainServer.Logger).Log("msg", "Could not initialize HSM engine", "err", err)
			os.Exit(1)
		}
		engine = hsmEngine
	case "gopem":
		gopemEngine, err := cryptoengines.NewGolangPEMEngine(mainServer.Logger, config.GopemData)
		if err != nil {
			level.Error(mainServer.Logger).Log("msg", "Could not initialize Golang PEM engine", "err", err)
			os.Exit(1)
		}
		engine = gopemEngine
	default:
		level.Error(mainServer.Logger).Log("msg", "Engine not supported")
		os.Exit(1)
	}

	level.Info(mainServer.Logger).Log("msg", "Engine initialized")
	level.Info(mainServer.Logger).Log("msg", fmt.Sprintf("Engine options: %v", engine.GetEngineConfig()))*/

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable", config.PostgresHostname, config.PostgresUsername, config.PostgresPassword, config.PostgresDatabase, config.PostgresPort)
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

	certificateRepository := postgresRepository.NewPostgresDB(db, mainServer.Logger)

	var s service.Service
	s, err = service.NewVaultService(config.VaultAddress, config.VaultPkiCaPath, config.VaultRoleID, config.VaultSecretID, config.VaultCA, config.VaultUnsealKeysFile, config.OcspUrl, certificateRepository, mainServer.Logger)
	if err != nil {
		level.Error(mainServer.Logger).Log("err", err, "msg", "Could not start connection with Vault Secret Engine")
		os.Exit(1)
	}
	s = service.NewAMQPMiddleware(mainServer.AmqpPublisher, mainServer.Logger)(s)
	s = service.NewInputValudationMiddleware()(s)
	s = service.LoggingMiddleware(mainServer.Logger)(s)

	mainServer.AddHttpHandler("/v1/", http.StripPrefix("/v1", transport.MakeHTTPHandler(s, log.With(mainServer.Logger, "component", "HTTPS"), opentracing.GlobalTracer())))

	errs := make(chan error)
	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errs <- fmt.Errorf("%s", <-c)
	}()

	mainServer.Run(errs)
	level.Info(mainServer.Logger).Log("exit", <-errs)
}
