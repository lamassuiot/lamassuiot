package main

import (
	"fmt"

	lamassu "github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/sdk/v3"
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

	conf, err := cconfig.LoadConfig[config.CAConfig](nil)
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

	lKMSClient := helpers.SetupLogger(conf.KMSClient.LogLevel, "Device Manager", "LMS SDK - KMS Client")
	kmsHttpCli, err := sdk.BuildHTTPClient(conf.KMSClient.HTTPClient, lKMSClient)
	if err != nil {
		log.Fatalf("could not build HTTP KMS Client: %s", err)
	}

	kmsSDK := sdk.NewHttpKMSClient(
		sdk.HttpClientWithSourceHeaderInjector(kmsHttpCli, models.DeviceManagerSource),
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
