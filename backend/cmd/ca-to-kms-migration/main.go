package main

import (
	"context"
	"flag"
	"os"

	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/migration/catokms"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	log "github.com/sirupsen/logrus"
)

func main() {
	dryRun := flag.Bool("dry-run", false, "scan and report without writing to KMS storage")
	flag.Parse()

	log.SetFormatter(helpers.LogFormatter)

	conf, err := cconfig.LoadConfig[catokms.Config](nil)
	if err != nil {
		log.Fatalf("could not load config: %s", err)
	}

	lvl, err := log.ParseLevel(string(conf.LogLevel))
	if err != nil {
		log.Warn("unknown log level; defaulting to 'info'")
		lvl = log.InfoLevel
	}
	log.SetLevel(lvl)

	logger := helpers.SetupLogger(conf.LogLevel, "Migration", "ca-to-kms")
	if *dryRun {
		logger.Info("running in DRY-RUN mode — NO WRITES will occur")
	}

	result, err := catokms.MigrateWithConfig(context.Background(), logger, conf.CAStorage, conf.KMSStorage, *dryRun)
	if err != nil {
		log.Fatalf("migration failed: %s", err)
	}
	if result.Failed > 0 {
		os.Exit(1)
	}
}
