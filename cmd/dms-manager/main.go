package main

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/v2/core/pkg/clients"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/models"
	lamassu "github.com/lamassuiot/lamassuiot/v2/pkg/assemblers"
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

	conf, err := config.LoadConfig[config.DMSconfig](nil)
	if err != nil {
		log.Fatal(err)
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

	lCAClient := helpers.SetupLogger(conf.CAClient.LogLevel, "DMS Manager", "LMS SDK - CA Client")
	caHttpCli, err := clients.BuildHTTPClient(conf.CAClient.HTTPClient, lCAClient)
	if err != nil {
		log.Fatalf("could not build HTTP CA Client: %s", err)
	}

	caSDK := clients.NewHttpCAClient(
		clients.HttpClientWithSourceHeaderInjector(caHttpCli, models.DMSManagerSource),
		fmt.Sprintf("%s://%s:%d%s", conf.CAClient.Protocol, conf.CAClient.Hostname, conf.CAClient.Port, conf.CAClient.BasePath),
	)
	lDeviceManagerClient := helpers.SetupLogger(conf.DevManagerClient.LogLevel, "DMS Manager", "LMS SDK - DeviceManager Client")
	deviceMngrHttpCli, err := clients.BuildHTTPClient(conf.DevManagerClient.HTTPClient, lDeviceManagerClient)
	if err != nil {
		log.Fatalf("could not build HTTP Device Manager Client: %s", err)
	}

	deviceSDK := clients.NewHttpDeviceManagerClient(
		clients.HttpClientWithSourceHeaderInjector(deviceMngrHttpCli, models.DMSManagerSource),
		fmt.Sprintf("%s://%s:%d%s", conf.DevManagerClient.Protocol, conf.DevManagerClient.Hostname, conf.DevManagerClient.Port, conf.DevManagerClient.BasePath),
	)

	_, _, err = lamassu.AssembleDMSManagerServiceWithHTTPServer(*conf, caSDK, deviceSDK, models.APIServiceInfo{
		Version:   version,
		BuildSHA:  sha1ver,
		BuildTime: buildTime,
	})
	if err != nil {
		log.Fatalf("could not run DMS Manager Server. Exiting: %s", err)
	}

	forever := make(chan struct{})
	<-forever
}
