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
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/transport"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/config"
	lamassudmsclient "github.com/lamassuiot/lamassuiot/pkg/dms-manager/client"
	esttransport "github.com/lamassuiot/lamassuiot/pkg/est/server/api/transport"
	clientUtils "github.com/lamassuiot/lamassuiot/pkg/utils/client"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server"
	"github.com/uptrace/opentelemetry-go-extra/otelgorm"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"

	badgerRepository "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/repository/badger"
	postgresRepository "github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/repository/postgres"
)

func main() {
	config := config.NewDeviceManagerConfig()
	mainServer := server.NewServer(config)

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable", config.PostgresHostname, config.PostgresUser, config.PostgresPassword, config.PostgresDatabase, config.PostgresPort)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: gormLogger.Default.LogMode(gormLogger.Silent),
	})
	if err != nil {
		level.Error(mainServer.Logger).Log("msg", "failed to connect to postgres", "err", err)
		os.Exit(1)
	}

	if err := db.Use(otelgorm.NewPlugin()); err != nil {
		level.Error(mainServer.Logger).Log("msg", "Could not initialize OpenTelemetry DB-GORM plugin", "err", err)
		os.Exit(1)
	}

	statsRepo, err := badgerRepository.NewStatisticsDBInMemory()
	if err != nil {
		level.Error(mainServer.Logger).Log("msg", "failed to connect to badger", "err", err)
		os.Exit(1)
	}
	deviceRepo := postgresRepository.NewDevicesPostgresDB(db, mainServer.Logger)
	logsRepo := postgresRepository.NewLogsPostgresDB(db, mainServer.Logger)

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

	var dmsClient lamassudmsclient.LamassuDMSManagerClient
	parsedLamassuDMSURL, err := url.Parse(config.LamassuDMSManagerAddress)
	if err != nil {
		level.Error(mainServer.Logger).Log("msg", "Could not parse DMS URL", "err", err)
		os.Exit(1)
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
			level.Error(mainServer.Logger).Log("msg", "Could not create LamassuDMSManager client", "err", err)
			os.Exit(1)
		}
	} else {
		dmsClient, err = lamassudmsclient.NewLamassuDMSManagerClientConfig(clientUtils.BaseClientConfigurationuration{
			URL:        parsedLamassuDMSURL,
			AuthMethod: clientUtils.AuthMethodNone,
		})
		if err != nil {
			level.Error(mainServer.Logger).Log("msg", "Could not create LamassuDMSManager client", "err", err)
			os.Exit(1)
		}
	}

	var s service.Service
	{
		s = service.NewDeviceManagerService(mainServer.Logger, deviceRepo, logsRepo, statsRepo, config.MinimumReenrollDays, caClient, dmsClient)
		s = service.NewAMQPMiddleware(mainServer.AmqpPublisher, mainServer.Logger)(s)
		s = service.NewInputValudationMiddleware()(s)
		s = service.LoggingMiddleware(mainServer.Logger)(s)
	}

	mainServer.AddHttpHandler("/v1/", http.StripPrefix("/v1", transport.MakeHTTPHandler(s, log.With(mainServer.Logger, "component", "HTTPS"))))
	mainServer.AddHttpHandler("/.well-known/", esttransport.MakeHTTPHandler(s, mainServer.Logger))
	mainServer.AddAmqpConsumer(config.ServiceName, []string{"io.lamassuiot.certificate.update", "io.lamassuiot.certificate.revoke"}, transport.MakeAmqpHandler(s, mainServer.Logger))

	errs := make(chan error)
	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errs <- fmt.Errorf("%s", <-c)
	}()

	mainServer.Run(errs)
	level.Info(mainServer.Logger).Log("exit", <-errs)
}
