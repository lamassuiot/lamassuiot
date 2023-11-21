package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/fatih/color"
	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/test/monolithic"
	rabbitmq_test "github.com/lamassuiot/lamassuiot/pkg/v3/test/subsystems/async-messaging/rabbitmq"
	awskmssm_test "github.com/lamassuiot/lamassuiot/pkg/v3/test/subsystems/cryptoengines/aws-kms-sm"
	keyvaultkv2_test "github.com/lamassuiot/lamassuiot/pkg/v3/test/subsystems/cryptoengines/keyvaultkv2"
	softhsmv2_test "github.com/lamassuiot/lamassuiot/pkg/v3/test/subsystems/cryptoengines/softhsmv2"
	postgres_test "github.com/lamassuiot/lamassuiot/pkg/v3/test/subsystems/storage/postgres"
)

const readyToPKI = ` 
________   _______    ________   ________       ___    ___      _________   ________          ________   ___  __     ___     
|\   __  \ |\  ___ \  |\   __  \ |\   ___ \     |\  \  /  /|    |\___   ___\|\   __  \        |\   __  \ |\  \|\  \  |\  \    
\ \  \|\  \\ \   __/| \ \  \|\  \\ \  \_|\ \    \ \  \/  / /    \|___ \  \_|\ \  \|\  \       \ \  \|\  \\ \  \/  /|_\ \  \   
 \ \   _  _\\ \  \_|/__\ \   __  \\ \  \ \\ \    \ \    / /          \ \  \  \ \  \\\  \       \ \   ____\\ \   ___  \\ \  \  
  \ \  \\  \|\ \  \_|\ \\ \  \ \  \\ \  \_\\ \    \/  /  /            \ \  \  \ \  \\\  \       \ \  \___| \ \  \\ \  \\ \  \ 
   \ \__\\ _\ \ \_______\\ \__\ \__\\ \_______\ __/  / /               \ \__\  \ \_______\       \ \__\     \ \__\\ \__\\ \__\
    \|__|\|__| \|_______| \|__|\|__| \|_______||\___/ /                 \|__|   \|_______|        \|__|      \|__| \|__| \|__|
                                               \|___|/                                                                        
`

func main() {
	hsmModule := flag.String("hsm-module-path", "", "enable HSM support")

	awsIoTManager := flag.Bool("awsiot", false, "enable AWS IoT Manager")
	awsIoTManagerUser := flag.String("awsiot-keyid", "", "AWS IoT Manager AccessKeyID")
	awsIoTManagerPass := flag.String("awsiot-keysecret", "", "AWS IoT Manager SecretAccessKey")
	awsIoTManagerRegion := flag.String("awsiot-region", "eu-west-1", "AWS IoT Manager Region")
	awsIoTManagerID := flag.String("awsiot-id", "", "AWS IoT Manager ConnectorID")
	flag.Parse()

	fmt.Println("===================== FLAGS ======================")

	fmt.Printf("AWS IoT Manager Enabled: %v\n", *awsIoTManager)
	if *awsIoTManager {
		ai := *awsIoTManagerID
		fmt.Printf("AWS IoT Manager ConnectorID: %s\n", ai)
		fmt.Printf("AWS IoT Manager AccessKey: %s\n", *awsIoTManagerUser)
		fmt.Printf("AWS IoT Manager SecretAccessKey: %s\n", *awsIoTManagerPass)
		fmt.Printf("AWS IoT Manager Region: %s\n", *awsIoTManagerRegion)
	}

	if *hsmModule != "" {
		fmt.Printf("HSM - PKCS11 Module Driver: %s\n", *hsmModule)
	}

	fmt.Println("========== LAUNCHING AUXILIARY SERVICES ==========")
	fmt.Println("Storage Engine")
	fmt.Println(">> launching docker: Postgres ...")
	pCleanup, storageConfig, err := postgres_test.RunPostgresDocker([]string{"ca", "alerts", "dmsmanager", "devicemanager", "cloudproxy"})
	if err != nil {
		log.Fatalf("could not launch Postgres: %s", err)
	}

	fmt.Printf(" 	-- postgres port: %d\n", storageConfig.Port)
	fmt.Printf(" 	-- postgres user: %s\n", storageConfig.Username)
	fmt.Printf(" 	-- postgres pass: %s\n", storageConfig.Password)

	fmt.Println("Crypto Engines")
	fmt.Println(">> launching docker: Hashicorp Vault ...")
	vCleanup, vaultConfig, err := keyvaultkv2_test.RunHashicorpVaultDocker()
	if err != nil {
		log.Fatalf("could not launch Hashicorp Vault: %s", err)
	}
	fmt.Println(">> launching docker: AWS Platform (Secrets Manager + KMS) ...")
	awsCleanup, awsCfg, err := awskmssm_test.RunAWSEmulationLocalStackDocker()
	if err != nil {
		log.Fatalf("could not launch AWS Platform: %s", err)
	}

	hsmModulePath := *hsmModule
	var softhsmCleanup func() error
	var pkcs11Cfg *config.PKCS11Config
	if hsmModulePath != "" {
		fmt.Println(">> launching docker: SoftHSM ...")
		softhsmCleanup, pkcs11Cfg, err = softhsmv2_test.RunSoftHsmV2Docker(hsmModulePath)
		if err != nil {
			log.Fatalf("could not launch SoftHSM: %s", err)
		}
	}

	fmt.Println("Async Messaging Engine")
	fmt.Println(">> launching docker: RabbitMQ ...")
	rmqCleanup, rmqConfig, err := rabbitmq_test.RunRabbitMQDocker()
	if err != nil {
		log.Fatalf("could not launch RabbitMQ: %s", err)
	}

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
		svcCleanup("RabbitMQ", rmqCleanup)
		svcCleanup("AWS-LocalStack", awsCleanup)
		if hsmModulePath != "" {
			svcCleanup("SoftHSM V2", softhsmCleanup)
		}
	}

	//capture future panics
	defer func() {
		if err := recover(); err != nil {
			printWColor(" !! Panic !! ", color.FgWhite, color.BgRed)
			fmt.Println()

			printWColor("cleaning up", color.FgRed, color.BgBlack)
			fmt.Println()
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
			Logs:           config.BaseConfigLogging{Level: config.Trace},
			AMQPConnection: *rmqConfig,
		},
		Domain:       "dev.lamassu.test",
		GatewayPort:  8443,
		AssemblyMode: config.Http,
		CryptoEngines: config.CryptoEngines{
			LogLevel:      config.Info,
			DefaultEngine: "dockertest-hcpvault-kvv2",
			HashicorpVaultKV2Provider: []config.HashicorpVaultCryptoEngineConfig{
				config.HashicorpVaultCryptoEngineConfig{
					HashicorpVaultSDK: *vaultConfig,
					ID:                "dockertest-hcpvault-kvv2",
					Metadata:          make(map[string]interface{}),
				},
			},
			AWSKMSProvider: []config.AWSCryptoEngine{
				config.AWSCryptoEngine{
					AWSSDKConfig: *awsCfg,
					ID:           "dockertest-localstack-kms",
					Metadata:     make(map[string]interface{}),
				},
			},
			AWSSecretsManagerProvider: []config.AWSCryptoEngine{
				config.AWSCryptoEngine{
					AWSSDKConfig: *awsCfg,
					ID:           "dockertest-localstack-smngr",
					Metadata:     make(map[string]interface{}),
				},
			},
			GolangProvider: []config.GolangEngineConfig{
				config.GolangEngineConfig{
					ID:               "golang-1",
					Metadata:         make(map[string]interface{}),
					StorageDirectory: "/tmp/gotest",
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
		AWSIoTManager: config.MonolithicAWSIoTManagerConfig{
			Enabled:     *awsIoTManager,
			ConnectorID: *awsIoTManagerID,
			AWSSDKConfig: config.AWSSDKConfig{
				AccessKeyID:     *awsIoTManagerUser,
				SecretAccessKey: config.Password(*awsIoTManagerPass),
				Region:          *awsIoTManagerRegion,
			},
		},
	}

	if hsmModulePath != "" {
		conf.CryptoEngines.PKCS11Provider = append(conf.CryptoEngines.PKCS11Provider, config.PKCS11EngineConfig{
			PKCS11Config: *pkcs11Cfg,
			ID:           "softhsm-test",
			Metadata:     make(map[string]interface{}),
		})
	}

	err = monolithic.RunMonolithicLamassuPKI(conf)
	if err != nil {
		panic(err)
	}

	fmt.Println(readyToPKI)

	forever := make(chan struct{})
	<-forever

}

func printWColor(str string, fg, bg color.Attribute) {
	color.Set(fg)
	color.Set(bg)
	fmt.Println(str)
	color.Unset()
}
