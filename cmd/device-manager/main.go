package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
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
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"

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
		panic(err)
	}

	deviceRepo := postgresRepository.NewDevicesPostgresDB(db, mainServer.Logger)
	caClient, err := lamassucaclient.NewLamassuCAClient(clientUtils.BaseClientConfigurationuration{
		URL: &url.URL{
			Scheme: "https",
			Host:   config.LamassuCAAddress,
		},
		AuthMethod: clientUtils.AuthMethodMutualTLS,
		AuthMethodConfig: &clientUtils.MutualTLSConfig{
			ClientCert: config.CertFile,
			ClientKey:  config.KeyFile,
		},
		CACertificate: config.LamassuCACertFile,
	})
	if err != nil {
		level.Error(mainServer.Logger).Log("msg", "Could not connect to LamassuCA", "err", err)
		os.Exit(1)
	}

	dmsClient, err := lamassudmsclient.NewLamassuDMSManagerClientConfig(clientUtils.BaseClientConfigurationuration{
		URL: &url.URL{
			Scheme: "https",
			Host:   config.DMSManagerAddress,
		},
		AuthMethod: clientUtils.AuthMethodMutualTLS,
		AuthMethodConfig: &clientUtils.MutualTLSConfig{
			ClientCert: config.CertFile,
			ClientKey:  config.KeyFile,
		},
		CACertificate: config.LamassuCACertFile,
	})
	if err != nil {
		level.Error(mainServer.Logger).Log("msg", "Could not connect to LamassuDMSManager", "err", err)
		os.Exit(1)
	}

	var s service.Service
	{
		s = service.NewDeviceManagerService(mainServer.Logger, deviceRepo, nil, nil, config.MinimumReenrollDays, caClient, dmsClient)
		s = service.LoggingMiddleware(mainServer.Logger)(s)
	}

	mainServer.AddHttpHandler("/v1/", http.StripPrefix("/v1", transport.MakeHTTPHandler(s, log.With(mainServer.Logger, "component", "HTTPS"), mainServer.Tracer)))
	mainServer.AddHttpHandler("/.well-known/", esttransport.MakeHTTPHandler(s, mainServer.Logger, mainServer.Tracer))

	errs := make(chan error)
	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errs <- fmt.Errorf("%s", <-c)
	}()

	mainServer.Run(errs)
	level.Info(mainServer.Logger).Log("exit", <-errs)
}
