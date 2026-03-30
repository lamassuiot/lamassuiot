package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime/coverage"
	"syscall"

	"github.com/lamassuiot/authz/pkg/api"
	authzconfig "github.com/lamassuiot/authz/pkg/config"
	"github.com/sirupsen/logrus"
	_ "gocloud.dev/blob/fileblob"
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
	configPath := flag.String("config", "config.yaml", "Path to the YAML configuration file")
	preloadDir := flag.String("preload", "", "Directory of policy JSON files to initialize on startup")
	flag.Parse()

	// Ensure the directory exists
	covDir := "./covdata"
	if _, err := os.Stat(covDir); os.IsNotExist(err) {
		os.Mkdir(covDir, 0755)
	}

	// Load configuration from YAML file
	appCfg, err := authzconfig.LoadAppConfig(*configPath)
	if err != nil {
		logrus.Fatalf("Failed to load configuration from %q: %v", *configPath, err)
	}

	// Map pkg/config types to api.Config
	credentials := make(map[string]api.CredentialConfig, len(appCfg.Credentials))
	for name, cred := range appCfg.Credentials {
		credentials[name] = api.CredentialConfig{
			Username: cred.Username,
			Password: cred.Password,
			Host:     cred.Host,
			Port:     cred.Port,
			Database: cred.Database,
		}
	}

	apiCfg := api.Config{
		Debug:       appCfg.Debug,
		Schemas:     appCfg.Schemas,
		Credentials: credentials,
		PreloadDir:  *preloadDir,
	}

	// Setup signal listener to flush coverage while running
	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGUSR1)
		for {
			<-sigs
			logrus.Info("Flushing coverage counters...")
			if err := coverage.WriteCountersDir(covDir); err != nil {
				logrus.Errorf("error writing coverage: %v", err)
			} else {
				logrus.Info("Coverage flushed successfully")
			}
		}
	}()

	logrus.Info("Database and Policy Store initialized")

	// Start your service in a goroutine if you want main to continue,
	// but usually Assemble functions block. If this blocks, the signal
	// handler above still works because it's in its own goroutine.
	go api.AssembleAuthzServiceWithHTTPServer(apiCfg)

	fmt.Println(readyToAuthz)

	// Keep alive
	forever := make(chan struct{})
	<-forever
}
