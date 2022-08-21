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
	cryptoengines "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/service/crypto-engines"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/api/transport"
	"github.com/lamassuiot/lamassuiot/pkg/ca/server/config"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"

	postgresRepository "github.com/lamassuiot/lamassuiot/pkg/ca/server/api/repository/postgres"
)

func main() {
	config := config.NewCAConfig()
	mainServer := server.NewServer(config)

	engine, err := cryptoengines.NewHSMPEngine(mainServer.Logger, "/home/ikerlan/pkcs11-proxy/libpkcs11-proxy.so.0.1", "lamassuHSM", "1234")
	if err != nil {
		level.Error(mainServer.Logger).Log("msg", "Could not initialize HSM engine", "err", err)
		os.Exit(1)
	}

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable", config.PostgresHostname, config.PostgresUser, config.PostgresPassword, config.PostgresDatabase, config.PostgresPort)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: gormLogger.Default.LogMode(gormLogger.Silent),
	})
	if err != nil {
		level.Error(mainServer.Logger).Log("msg", "Could not connect to Postgres", "err", err)
		os.Exit(1)
	}

	certificateRepository := postgresRepository.NewPostgresDB(db, mainServer.Logger)

	var s service.Service
	{
		s = service.LoggingMiddleware(mainServer.Logger)(s)
		s = service.NewAMQPMiddleware(mainServer.AmqpChannel, mainServer.Logger)(s)
		s = service.NewCAService(mainServer.Logger, engine, certificateRepository, config.OcspUrl)
	}

	mainServer.AddHttpHandler("/v1/", http.StripPrefix("/v1", transport.MakeHTTPHandler(s, log.With(mainServer.Logger, "component", "HTTPS"), mainServer.Tracer)))

	errs := make(chan error)
	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errs <- fmt.Errorf("%s", <-c)
	}()

	mainServer.Run(errs)
	level.Info(mainServer.Logger).Log("exit", <-errs)
}
