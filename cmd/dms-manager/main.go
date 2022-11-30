package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	lamassucaclient "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/transport"
	"github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/config"
	clientUtils "github.com/lamassuiot/lamassuiot/pkg/utils/client"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"

	postgresRepository "github.com/lamassuiot/lamassuiot/pkg/dms-manager/server/api/repository/postgres"
)

func main() {
	config := config.NewDMSManagerConfig()
	mainServer := server.NewServer(config)

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable", config.PostgresHostname, config.PostgresUser, config.PostgresPassword, config.PostgresDatabase, config.PostgresPort)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: gormLogger.Default.LogMode(gormLogger.Silent),
	})
	if err != nil {
		panic(err)
	}

	dmsRepo := postgresRepository.NewPostgresDB(db, mainServer.Logger)

	var caClient lamassucaclient.LamassuCAClient
	parsedLamassuCAURL, err := url.Parse(config.LamassuCAAddress)
	if err != nil {
		level.Error(mainServer.Logger).Log("msg", "Could not parse CA URL", "err", err)
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
			level.Error(mainServer.Logger).Log("msg", "Could not create LamassuCA client", "err", err)
			os.Exit(1)
		}
	} else {
		caClient, err = lamassucaclient.NewLamassuCAClient(clientUtils.BaseClientConfigurationuration{
			URL:        parsedLamassuCAURL,
			AuthMethod: clientUtils.AuthMethodNone,
		})
		if err != nil {
			level.Error(mainServer.Logger).Log("msg", "Could not create LamassuCA client", "err", err)
			os.Exit(1)
		}
	}

	var s service.Service
	{
		s = service.NewDMSManagerService(mainServer.Logger, dmsRepo, &caClient)
		s = service.NewAMQPMiddleware(mainServer.AmqpPublisher, mainServer.Logger)(s)
		s = service.NewInputValudationMiddleware()(s)
		s = service.LoggingMiddleware(mainServer.Logger)(s)
	}

	mainServer.AddHttpHandler("/v1/", http.StripPrefix("/v1", transport.MakeHTTPHandler(s, log.With(mainServer.Logger, "component", "HTTPS"))))

	errs := make(chan error)
	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errs <- fmt.Errorf("%s", <-c)
	}()

	mainServer.Run(errs)
	level.Info(mainServer.Logger).Log("exit", <-errs)
}
