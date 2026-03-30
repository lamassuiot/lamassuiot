package main

import (
	"flag"
	"fmt"

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
		Port:        8888,
		Schemas:     appCfg.Schemas,
		Credentials: credentials,
		PreloadDir:  *preloadDir,
	}

	logrus.Info("Database and Policy Store initialized")

	if _, err := api.AssembleAuthzServiceWithHTTPServer(apiCfg); err != nil {
		logrus.Fatalf("Failed to start Authz service: %v", err)
	}

	fmt.Println(readyToAuthz)

	// Keep alive
	forever := make(chan struct{})
	<-forever
}
