package main

import (
	"fmt"

	lamassu "github.com/lamassuiot/lamassuiot/v2/pkg/assemblers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/clients"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
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

	conf, err := config.LoadConfig[config.CAConfig](nil)
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

	lKMSClient := helpers.SetupLogger(conf.KMSClient.LogLevel, "CA SDK", "HTTP Client")
	kmsHttpCli, err := clients.BuildHTTPClient(conf.KMSClient.HTTPClient, lKMSClient)
	if err != nil {
		log.Fatalf("could not build HTTP CA Client: %s", err)
	}

	kmsSDK := clients.NewHttpKMSClient(
		clients.HttpClientWithSourceHeaderInjector(kmsHttpCli, models.CASource),
		fmt.Sprintf("%s://%s:%d%s", conf.KMSClient.Protocol, conf.KMSClient.Hostname, conf.KMSClient.Port, conf.KMSClient.BasePath),
	)

	_, _, _, err = lamassu.AssembleCAServiceWithHTTPServer(*conf, kmsSDK, models.APIServiceInfo{
		Version:   version,
		BuildSHA:  sha1ver,
		BuildTime: buildTime,
	})
	if err != nil {
		log.Fatalf("could not run CA Server. Exiting: %s", err)
	}

	forever := make(chan struct{})
	<-forever
}
