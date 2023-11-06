package main

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/pkg/lamassu"
	"github.com/lamassuiot/lamassuiot/pkg/v3/clients"
	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
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

	conf, err := config.LoadConfig[config.IotAWS]()
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

	lDMSClient := helpers.ConfigureLogger(conf.DMSManagerClient.LogLevel, "LMS SDK - DMS Client")
	lDeviceClient := helpers.ConfigureLogger(conf.DevManagerClient.LogLevel, "LMS SDK - Device Client")
	lCAClient := helpers.ConfigureLogger(conf.CAClient.LogLevel, "LMS SDK - CA Client")

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

	dmsSDK := clients.NewHttpDMSManagerClient(dmsHttpCli, fmt.Sprintf("%s://%s:%d%s", conf.DMSManagerClient.Protocol, conf.DMSManagerClient.Hostname, conf.DMSManagerClient.Port, conf.DMSManagerClient.BasePath))
	deviceSDK := clients.NewHttpDeviceManagerClient(deviceHttpCli, fmt.Sprintf("%s://%s:%d%s", conf.DevManagerClient.Protocol, conf.DevManagerClient.Hostname, conf.DevManagerClient.Port, conf.DevManagerClient.BasePath))
	caSDK := clients.NewHttpCAClient(caHttpCli, fmt.Sprintf("%s://%s:%d%s", conf.CAClient.Protocol, conf.CAClient.Hostname, conf.CAClient.Port, conf.CAClient.BasePath))

	_, err = lamassu.AssembleAWSIoTManagerService(*conf, caSDK, dmsSDK, deviceSDK)
	if err != nil {
		log.Fatalf("could not run AWS IoT Manager. Exiting: %s", err)
	}

	forever := make(chan struct{})
	<-forever
}
