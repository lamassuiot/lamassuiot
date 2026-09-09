package main

import (
	"context"
	"fmt"
	"os"
	"slices"

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

const usage = `Usage: authz [COMMAND]

With no command, runs the Authz service.

Commands:
  init                    Apply migrations, preload policies and seed bootstrap principals, then exit
  migrate up              Apply all pending migrations
  migrate up-to VERSION   Apply migrations up to VERSION
  migrate status          Show the state of every migration
  migrate version         Print the current database version
  migrate down --confirm  Roll back the last applied migration. One step at a time, so
                          what it undoes depends on the current version; rolling back far
                          enough reaches the initial migration, which drops principals,
                          principal_policies and policies. Check 'migrate status' first.

Configuration is read from the usual config file, so no connection string is needed.`

// runCommand dispatches the one-shot subcommands. Returning an error (rather
// than exiting) keeps the non-zero exit in one place, which is what a Kubernetes
// Job needs to decide whether the step succeeded.
func runCommand(ctx context.Context, conf authzconfig.AuthzConfig, command string, args []string) error {
	switch command {
	case "init":
		return api.InitializeStorage(ctx, conf)

	case "migrate":
		if len(args) == 0 {
			return fmt.Errorf("migrate requires a subcommand\n\n%s", usage)
		}
		sub, subArgs := args[0], args[1:]

		// Rolling back the authz schema eventually reaches the initial migration,
		// which drops principals, principal_policies and policies. Which step a
		// given "down" undoes depends on the current version, so gate them all.
		if sub == "down" && !slices.Contains(subArgs, "--confirm") {
			return fmt.Errorf("refusing to run %q without --confirm: rolling back this schema can drop principals, principal_policies and policies; check 'migrate status' first", sub)
		}
		subArgs = slices.DeleteFunc(subArgs, func(a string) bool { return a == "--confirm" })

		return api.RunMigrateCommand(ctx, conf, sub, subArgs)

	default:
		return fmt.Errorf("unknown command %q\n\n%s", command, usage)
	}
}

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

	if len(os.Args) > 1 {
		if err := runCommand(context.Background(), *conf, os.Args[1], os.Args[2:]); err != nil {
			log.Fatalf("%s", err)
		}
		return
	}

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
