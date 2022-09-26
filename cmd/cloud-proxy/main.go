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
	"github.com/hashicorp/consul/api"
	lamassucaclient "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/api/transport"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/config"
	clientUtils "github.com/lamassuiot/lamassuiot/pkg/utils/client"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server"
	"github.com/opentracing/opentracing-go"
	"github.com/uptrace/opentelemetry-go-extra/otelgorm"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"

	postgresRepository "github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/api/repository/postgres"
)

func main() {
	config := config.NewCloudProxyConfig()
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

	cloudProxyRepo := postgresRepository.NewPostgresDB(db)
	consulClient := initializeConsulClient(config.ConsulProtocol, config.ConsulHost, config.ConsulPort, config.ConsulCA, mainServer.Logger)

	lamassuCAClient, err := lamassucaclient.NewLamassuCAClient(clientUtils.BaseClientConfigurationuration{
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

	clientBaseConfig := clientUtils.BaseClientConfigurationuration{
		AuthMethod: clientUtils.AuthMethodNone,
		Insecure:   true,
	}

	if config.LamassuConnectorsMutualTLS {
		clientBaseConfig = clientUtils.BaseClientConfigurationuration{
			AuthMethod: clientUtils.AuthMethodMutualTLS,
			AuthMethodConfig: &clientUtils.MutualTLSConfig{
				ClientCert: config.CertFile,
				ClientKey:  config.KeyFile,
			},
			// CACertificate: config.LamassuConnectorsCertFile,
			Insecure: true,
		}
	}

	var s service.Service
	{
		s = service.NewCloudPorxyService(consulClient, cloudProxyRepo, lamassuCAClient, clientBaseConfig, mainServer.Logger)
		s = service.NewInputValudationMiddleware()(s)
		s = service.LoggingMiddleware(mainServer.Logger)(s)

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

func initializeConsulClient(consulProtocol string, consulHost string, consulPort string, consulCA string, logger log.Logger) *api.Client {
	consulConfig := api.DefaultConfig()
	if consulProtocol == "https" || consulProtocol == "http" {
		if (consulProtocol == "https" && consulPort == "443") || (consulProtocol == "http" && consulPort == "80") {
			consulConfig.Address = consulProtocol + "://" + consulHost
		} else {
			consulConfig.Address = consulProtocol + "://" + consulHost + ":" + consulPort
		}
	} else {
		level.Error(logger).Log("msg", "Unsuported consul protocol")
	}
	tlsConf := &api.TLSConfig{CAFile: consulCA}
	consulConfig.TLSConfig = *tlsConf
	consulClient, err := api.NewClient(consulConfig)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not start Consul API Client")
		os.Exit(1)
	}

	agent := consulClient

	level.Info(logger).Log("msg", "Connection established with Consul")

	return agent
}
