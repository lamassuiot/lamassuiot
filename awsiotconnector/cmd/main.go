package main

import (
	"fmt"

	lamassu "github.com/lamassuiot/lamassuiot/v2/awsiotconnector/pkg"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/clients"
	cconfig "github.com/lamassuiot/lamassuiot/v2/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

var (
	version   string = "v0"    // api version
	sha1ver   string = "-"     // sha1 revision used to build the program
	buildTime string = "devTS" // when the executable was built
)

func main() {
	log.SetFormatter(helpers.LogFormatter)
	log.Infof("starting api: version=%s buildTime=%s sha1ver=%s", version, buildTime, sha1ver)

	conf, err := cconfig.LoadConfig[config.IotAWS](&config.IotAWSDefaults)
	if err != nil {
		log.Fatalf("something went wrong while loading config. Exiting: %s", err)
	}

	globalLogLevel, err := log.ParseLevel(string(conf.Logs.Level))
	if err != nil {
		log.Warn("unknown log level. defaulting to 'info' log level")
		globalLogLevel = log.InfoLevel
	}
	log.SetLevel(globalLogLevel)

	log.Infof("global log level set to '%s'", globalLogLevel)

	confBytes, err := yaml.Marshal(conf)
	if err != nil {
		log.Fatalf("could not dump yaml config: %s", err)
	}

	log.Debugf("===================================================")
	log.Debugf("%s", confBytes)
	log.Debugf("===================================================")

	lDMSClient := helpers.SetupLogger(conf.DMSManagerClient.LogLevel, "AWS IoT Connector", "LMS SDK - DMS Client")
	lDeviceClient := helpers.SetupLogger(conf.DevManagerClient.LogLevel, "AWS IoT Connector", "LMS SDK - Device Client")
	lCAClient := helpers.SetupLogger(conf.CAClient.LogLevel, "AWS IoT Connector", "LMS SDK - CA Client")

	dmsHttpCli, err := clients.BuildHTTPClient(conf.DMSManagerClient.HTTPClient, lDMSClient)
	if err != nil {
		log.Fatalf("could not build HTTP DMS Manager Client: %s", err)
	}

	deviceHttpCli, err := clients.BuildHTTPClient(conf.DevManagerClient.HTTPClient, lDeviceClient)
	if err != nil {
		log.Fatalf("could not build HTTP Device Client: %s", err)
	}

	caHttpCli, err := clients.BuildHTTPClient(conf.CAClient.HTTPClient, lCAClient)
	if err != nil {
		log.Fatalf("could not build HTTP CA Client: %s", err)
	}

	dmsSDK := clients.NewHttpDMSManagerClient(
		clients.HttpClientWithSourceHeaderInjector(dmsHttpCli, models.AWSIoTSource(conf.ConnectorID)),
		fmt.Sprintf("%s://%s:%d%s", conf.DMSManagerClient.Protocol, conf.DMSManagerClient.Hostname, conf.DMSManagerClient.Port, conf.DMSManagerClient.BasePath),
	)
	deviceSDK := clients.NewHttpDeviceManagerClient(
		clients.HttpClientWithSourceHeaderInjector(deviceHttpCli, models.AWSIoTSource(conf.ConnectorID)),
		fmt.Sprintf("%s://%s:%d%s", conf.DevManagerClient.Protocol, conf.DevManagerClient.Hostname, conf.DevManagerClient.Port, conf.DevManagerClient.BasePath),
	)
	caSDK := clients.NewHttpCAClient(
		clients.HttpClientWithSourceHeaderInjector(caHttpCli, models.AWSIoTSource(conf.ConnectorID)),
		fmt.Sprintf("%s://%s:%d%s", conf.CAClient.Protocol, conf.CAClient.Hostname, conf.CAClient.Port, conf.CAClient.BasePath),
	)

	_, err = lamassu.AssembleAWSIoTManagerService(*conf, caSDK, dmsSDK, deviceSDK)
	if err != nil {
		log.Fatalf("could not run AWS IoT Manager. Exiting: %s", err)
	}

	forever := make(chan struct{})
	<-forever
}
