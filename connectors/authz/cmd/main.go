package main

import (
	"fmt"

	"github.com/lamassuiot/authz/pkg/api"
	authzconfig "github.com/lamassuiot/authz/pkg/config"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

var (
	version   string = "v0"
	sha1ver   string = "-"
	buildTime string = "devTS"
)

const readyToAuthz = `
 $$$$$$\  $$\   $$\ $$$$$$$$\ $$\   $$\       $$$$$$$$\
$$  __$$\ $$ |  $$ |\__$$  __|$$ |  $$ |      \____$$  |
$$ /  $$ |$$ |  $$ |   $$ |   $$ |  $$ |           $$  /
$$$$$$$$ |$$ |  $$ |   $$ |   $$$$$$$$ |$$$$$$\   $$  /
$$  __$$ |$$ |  $$ |   $$ |   $$  __$$ |\______| $$  /
$$ |  $$ |$$ |  $$ |   $$ |   $$ |  $$ |        $$  /
$$ |  $$ |\$$$$$$  |   $$ |   $$ |  $$ |       $$$$$$$$\
\__|  \__| \______/    \__|   \__|  \__|       \________|`

func main() {
	log.SetFormatter(helpers.LogFormatter)
	log.Infof("starting api: version=%s buildTime=%s sha1ver=%s", version, buildTime, sha1ver)

	conf, err := cconfig.LoadConfig[authzconfig.AuthzConfig](nil)
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

	if _, _, _, _, _, err := api.AssembleAuthzServiceWithHTTPServer(*conf, models.APIServiceInfo{
		Version:   version,
		BuildSHA:  sha1ver,
		BuildTime: buildTime,
	}); err != nil {
		log.Fatalf("could not run Authz Server. Exiting: %s", err)
	}

	fmt.Println(readyToAuthz)

	forever := make(chan struct{})
	<-forever
}
