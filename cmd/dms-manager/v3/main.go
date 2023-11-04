package main

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/pkg/lamassu"
	"github.com/lamassuiot/lamassuiot/pkg/v3/clients"
	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/helpers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
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

	conf, err := config.LoadConfig[config.DMSconfig]()
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

	lCAClient := helpers.ConfigureLogger(conf.CAClient.LogLevel, "LMS SDK - CA Client")
	caHttpCli, err := clients.BuildHTTPClient(conf.CAClient.HTTPClient, lCAClient)
	if err != nil {
		log.Fatalf("could not build HTTP CA Client: %s", err)
	}

	caCli := clients.NewHttpCAClient(caHttpCli, fmt.Sprintf("%s://%s%s:%d", conf.CAClient.Protocol, conf.CAClient.Hostname, conf.CAClient.BasePath, conf.CAClient.Port))

	lDeviceManagerClient := helpers.ConfigureLogger(conf.CAClient.LogLevel, "LMS SDK - DeviceManager Client")
	deviceMngrHttpCli, err := clients.BuildHTTPClient(conf.DevManagerClient.HTTPClient, lDeviceManagerClient)
	if err != nil {
		log.Fatalf("could not build HTTP Device Manager Client: %s", err)
	}

	devManagerCli := clients.NewHttpDeviceManagerClient(deviceMngrHttpCli, fmt.Sprintf("%s://%s%s:%d", conf.DevManagerClient.Protocol, conf.DevManagerClient.Hostname, conf.DevManagerClient.BasePath, conf.DevManagerClient.Port))

	_, _, err = lamassu.AssembleDMSManagerServiceWithHTTPServer(*conf, caCli, devManagerCli, models.APIServiceInfo{
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
