package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/hashicorp/consul/api"
	lamassucaclient "github.com/lamassuiot/lamassuiot/pkg/ca/client"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/api/service"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/api/transport"
	"github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/config"
	clientUtils "github.com/lamassuiot/lamassuiot/pkg/utils/client"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server"
	gorm_logrus "github.com/onrik/gorm-logrus"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"

	postgresRepository "github.com/lamassuiot/lamassuiot/pkg/cloud-proxy/server/api/repository/postgres"
)

func main() {
	config := config.NewCloudProxyConfig()

	dbLogrus := gormLogger.Default.LogMode(gormLogger.Silent)
	if config.DebugMode {
		logrus.SetLevel(logrus.InfoLevel)
		dbLogrus = gorm_logrus.New()
		dbLogrus.LogMode(gormLogger.Info)
	}

	mainServer := server.NewServer(config)

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable", config.PostgresHostname, config.PostgresUsername, config.PostgresPassword, config.PostgresDatabase, config.PostgresPort)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: dbLogrus,
	})
	if err != nil {
		log.Fatal(err)
	}

	cloudProxyRepo := postgresRepository.NewPostgresDB(db)
	consulClient := initializeConsulClient(config.ConsulProtocol, config.ConsulHost, config.ConsulPort, config.ConsulCA)

	var lamassuCAClient lamassucaclient.LamassuCAClient
	parsedLamassuCAURL, err := url.Parse(config.LamassuCAAddress)
	if err != nil {
		log.Fatal("Could not parse CA URL: ", err)
	}

	if strings.HasPrefix(config.LamassuCAAddress, "https") {
		lamassuCAClient, err = lamassucaclient.NewLamassuCAClient(clientUtils.BaseClientConfigurationuration{
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
		lamassuCAClient, err = lamassucaclient.NewLamassuCAClient(clientUtils.BaseClientConfigurationuration{
			URL:        parsedLamassuCAURL,
			AuthMethod: clientUtils.AuthMethodNone,
		})
		if err != nil {
			log.Fatal("Could not create LamassuCA client: ", err)
		}
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

	var svc service.Service
	{
		svc = service.NewCloudPorxyService(consulClient, cloudProxyRepo, lamassuCAClient, clientBaseConfig)
		svc = service.NewInputValudationMiddleware()(svc)
		svc = service.LoggingMiddleware()(svc)

	}

	mainServer.AddHttpHandler("/v1/", http.StripPrefix("/v1", transport.MakeHTTPHandler(svc)))
	mainServer.AddAmqpConsumer(config.ServiceName, []string{"#"}, transport.MakeAmqpHandler(svc))

	mainServer.Run()
	forever := make(chan struct{})
	<-forever
}

func initializeConsulClient(consulProtocol string, consulHost string, consulPort string, consulCA string) *api.Client {
	consulConfig := api.DefaultConfig()
	if consulProtocol == "https" || consulProtocol == "http" {
		if (consulProtocol == "https" && consulPort == "443") || (consulProtocol == "http" && consulPort == "80") {
			consulConfig.Address = consulProtocol + "://" + consulHost
		} else {
			consulConfig.Address = consulProtocol + "://" + consulHost + ":" + consulPort
		}
	} else {
		log.Fatal("Unsuported consul protocol")
	}
	tlsConf := &api.TLSConfig{CAFile: consulCA}
	consulConfig.TLSConfig = *tlsConf
	consulClient, err := api.NewClient(consulConfig)
	if err != nil {
		log.Fatal("Could not start Consul API Client: ", err)
	}

	agent := consulClient

	log.Info("Connection established with Consul")

	return agent
}
