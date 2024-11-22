package main

import (
	"fmt"

	lamassu "github.com/lamassuiot/lamassuiot/v3/backend/pkg/assemblers"
	"github.com/lamassuiot/lamassuiot/v3/backend/pkg/config"
	cconfig "github.com/lamassuiot/lamassuiot/v3/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v3/sdk"
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

	conf, err := cconfig.LoadConfig[config.DeviceManagerConfig](nil)
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

	lCAClient := helpers.SetupLogger(conf.CAClient.LogLevel, "Device Manager", "LMS SDK - CA Client")
	caHttpCli, err := sdk.BuildHTTPClient(conf.CAClient.HTTPClient, lCAClient)
	if err != nil {
		log.Fatalf("could not build HTTP CA Client: %s", err)
	}

	caSDK := sdk.NewHttpCAClient(
		sdk.HttpClientWithSourceHeaderInjector(caHttpCli, models.DeviceManagerSource),
		fmt.Sprintf("%s://%s:%d%s", conf.CAClient.Protocol, conf.CAClient.Hostname, conf.CAClient.Port, conf.CAClient.BasePath),
	)

	_, _, err = lamassu.AssembleDeviceManagerServiceWithHTTPServer(*conf, caSDK, models.APIServiceInfo{
		Version:   version,
		BuildSHA:  sha1ver,
		BuildTime: buildTime,
	})
	if err != nil {
		log.Fatalf("could not run Device Manager Server. Exiting: %s", err)
	}

	forever := make(chan struct{})
	<-forever
}
