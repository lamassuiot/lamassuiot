// upgrade-check reports, on a 3.8 database already moved to the pki schemas, the conditions under which the v4
// upgrade migrations would abort. It only reads; see README.md.
package main

import (
	"context"
	"os"

	bconfig "github.com/lamassuiot/lamassuiot/v4/backend/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/upgradecheck"
	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	log "github.com/sirupsen/logrus"
)

var (
	version   string = "v0"    // api version
	sha1ver   string = "-"     // sha1 revision used to build the program
	buildTime string = "devTS" // when the executable was built
)

func main() {
	log.SetFormatter(helpers.LogFormatter)
	log.Infof("upgrade-check %s (%s, built %s)", version, sha1ver, buildTime)

	conf, err := cconfig.LoadConfig[bconfig.KMSConfig](nil)
	if err != nil {
		log.Errorf("could not load config: %s", err)
		os.Exit(2)
	}

	lvl, err := log.ParseLevel(string(conf.Logs.Level))
	if err != nil {
		log.Warn("unknown log level; defaulting to 'info'")
		lvl = log.InfoLevel
	}
	log.SetLevel(lvl)

	logger := helpers.SetupLogger(conf.Logs.Level, "Upgrade", "check")
	os.Exit(upgradecheck.RunWithConfig(context.Background(), logger, *conf, os.Stdout))
}
