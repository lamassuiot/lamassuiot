package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/fatih/color"
	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/test/monolithic"
	keyvaultkv2_test "github.com/lamassuiot/lamassuiot/pkg/v3/test/subsystems/cryptoengines/keyvaultkv2"
	postgres_test "github.com/lamassuiot/lamassuiot/pkg/v3/test/subsystems/storage/postgres"
)

const readyToPKI = ` 
________  _______   ________      ___    ___      _________  ________          ________  ___  __    ___     
|\   __  \|\  ___ \ |\   ___ \    |\  \  /  /|    |\___   ___\\   __  \        |\   __  \|\  \|\  \ |\  \    
\ \  \|\  \ \   __/|\ \  \_|\ \   \ \  \/  / /    \|___ \  \_\ \  \|\  \       \ \  \|\  \ \  \/  /|\ \  \   
 \ \   _  _\ \  \_|/_\ \  \ \\ \   \ \    / /          \ \  \ \ \  \\\  \       \ \   ____\ \   ___  \ \  \  
  \ \  \\  \\ \  \_|\ \ \  \_\\ \   \/  /  /            \ \  \ \ \  \\\  \       \ \  \___|\ \  \\ \  \ \  \ 
   \ \__\\ _\\ \_______\ \_______\__/  / /               \ \__\ \ \_______\       \ \__\    \ \__\\ \__\ \__\
    \|__|\|__|\|_______|\|_______|\___/ /                 \|__|  \|_______|        \|__|     \|__| \|__|\|__|
                                 \|___|/                                                                     `

func main() {
	fmt.Println("========== LAUNCHING AUXILIARY SERVICES ==========")
	fmt.Println("Storage Engine")
	fmt.Println(">> launching docker: Postgres ...")
	pCleanup, storageConfig, err := postgres_test.RunPostgresDocker([]string{"ca", "alerts", "dmsmanager", "devicemanager", "cloudproxy"})
	if err != nil {
		log.Fatalf("could not launch postgres: %s", err)
	}
	fmt.Println("Crypto Engines")
	fmt.Println(">> launching docker: Hashicorp Vault ...")
	vCleanup, vaultConfig, err := keyvaultkv2_test.RunHashicorpVaultDocker()
	if err != nil {
		log.Fatalf("could not launch postgres: %s", err)
	}

	fmt.Println(">> launching docker: SoftHSM ...")
	fmt.Println("Async Messaging Engine")
	fmt.Println(">> launching docker: RabbitMQ ...")
	fmt.Println("========== READY TO LAUNCH MONOLITHIC PKI ==========")

	cleanup := func() {
		fmt.Println("========== CLEANING UP ==========")
		svcCleanup := func(svcName string, cleaner func() error) {
			fmt.Printf(">> Cleaning %s ...\n", svcName)
			err = cleaner()
			if err != nil {
				fmt.Printf("could not cleanup %s: %s\n", svcName, err)
			}
		}

		svcCleanup("Postgres", pCleanup)
		svcCleanup("Hashicorp Vault", vCleanup)
	}

	//capture future panics
	defer func() {
		if err := recover(); err != nil {
			color.Set(color.BgRed)
			color.Set(color.FgWhite)
			fmt.Println(" !! Panic !! ")
			color.Unset()

			color.Set(color.FgRed)
			fmt.Println(err)
			color.Unset()
			fmt.Println("cleaning up")
			cleanup()
		}
	}()

	//capture CTRL+C
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for _ = range c {
			// sig is a ^C, handle it
			fmt.Println("ctrl+c triggered. Cleaning up")
			cleanup()
			os.Exit(0)
		}
	}()

	conf := config.MonolithicConfig{
		BaseConfig: config.BaseConfig{
			Logs: config.BaseConfigLogging{Level: config.Debug},
		},
		Domain:       "dev.lamassu.test",
		GatewayPort:  8443,
		AssemblyMode: config.Http,
		CryptoEngines: config.CryptoEngines{
			LogLevel:      config.Trace,
			DefaultEngine: "dockertest-hcpvault-kvv2",
			HashicorpVaultKV2Provider: []config.HashicorpVaultCryptoEngineConfig{
				config.HashicorpVaultCryptoEngineConfig{
					HashicorpVaultSDK: *vaultConfig,
					ID:                "dockertest-hcpvault-kvv2",
					Metadata:          make(map[string]interface{}),
				},
			},
		},
		CryptoMonitoring: config.CryptoMonitoring{
			Enabled:   true,
			Frequency: "* * * * *",
		},
		Storage: config.PluggableStorageEngine{
			LogLevel: config.Info,
			Provider: config.Postgres,
			Postgres: *storageConfig,
		},
	}

	err = monolithic.RunMonolithicLamassuPKI(conf)
	if err != nil {
		panic(err)
	}

	fmt.Println(readyToPKI)

	forever := make(chan struct{})
	<-forever

}
