package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/lamassuiot/lamassuiot/v2/pkg/clients"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/test/monolithic"
	rabbitmq_test "github.com/lamassuiot/lamassuiot/v2/pkg/test/subsystems/async-messaging/rabbitmq"
	awskmssm_test "github.com/lamassuiot/lamassuiot/v2/pkg/test/subsystems/cryptoengines/aws-kms-sm"
	keyvaultkv2_test "github.com/lamassuiot/lamassuiot/v2/pkg/test/subsystems/cryptoengines/keyvaultkv2"
	softhsmv2_test "github.com/lamassuiot/lamassuiot/v2/pkg/test/subsystems/cryptoengines/softhsmv2"
	couchdb_test "github.com/lamassuiot/lamassuiot/v2/pkg/test/subsystems/storage/couchdb"
	postgres_test "github.com/lamassuiot/lamassuiot/v2/pkg/test/subsystems/storage/postgres"
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

const lamassuLogo = `
                                                              ..                
                                                         ............           
                                                        ....       ....         
                                                       ...          ....        
                                                       ...          ....        
                                                       ...          ....        
 ..... .........................                                                
 ....                         ....                      ..............          
      ....                       ....                  .................        
     .....  ...................    ....                .....       .....        
                             .....   .....             ....         ....        
          .....  ...........    ....    ....           .....       .....        
           ..             ....    .....   .....        .......   .......        
                            ....     ....    ....      .......   .......        
                               ....    ....    ....     ...............         
                  ...........    ....     ....    ....    ..........    .       
                ...............     ...     ....    ....     .....    ....      
               ..................     ....     ...     ....        .......      
              ......................                             .........      
            ...    .......................................................      
            ..     .......................................................      
            ..     .......................................................      
            ..     .......................................................      
            ..     .......................................................      
            ..    ............ ........                    ...... ........      
           ..   ..........      .......                   ......   .......      
         ..     .......           .....                   .....     ......      
       .        .....              .....                 .....       .....      
                .....               .....               .....        .....      
                ..........           ........           .......       .......   
                ...........          ..........        ..........     ......... 
`

type CryptoEngineOption string

const (
	AwsSecretsManager CryptoEngineOption = "aws-secrets"
	AwsKms            CryptoEngineOption = "aws-kms"
	Vault             CryptoEngineOption = "vault"
	Pkcs11            CryptoEngineOption = "pkcs11"
	GolangFS          CryptoEngineOption = "golangfs"
)

func main() {
	hsmModule := flag.String("hsm-module-path", "", "enable HSM support")

	awsIoTManager := flag.Bool("awsiot", false, "enable AWS IoT Manager")
	awsIoTManagerUser := flag.String("awsiot-keyid", "", "AWS IoT Manager AccessKeyID")
	awsIoTManagerPass := flag.String("awsiot-keysecret", "", "AWS IoT Manager SecretAccessKey")
	awsIoTManagerRegion := flag.String("awsiot-region", "eu-west-1", "AWS IoT Manager Region")
	awsIoTManagerID := flag.String("awsiot-id", "", "AWS IoT Manager ConnectorID")

	cryptoEngineOptions := flag.String("cryptoengines", "golangfs", ", separated list of crypto engines to enable ['aws-secrets','aws-kms','vault','pkcs11','golangfs']")
	disableMonitor := flag.Bool("disable-monitor", false, "disable crypto monitoring")
	disableEventBus := flag.Bool("disable-eventbus", false, "disable eventbus")

	storageEngine := flag.String("storageengine", "postgres", "valid options: sqlite, postgres, couchdb")
	sqliteOptions := flag.String("sqlite", "", "set path to sqlite database to enable sqlite storage engine")

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

	cleanupMap := make(map[string]func() error)

	// By default, all crypto engines are enabled
	cryptoEngineOptionsMap := map[CryptoEngineOption]struct{}{
		AwsSecretsManager: {},
		AwsKms:            {},
		Vault:             {},
		Pkcs11:            {},
		GolangFS:          {},
	}

	if (*cryptoEngineOptions) != "" {
		var err error
		cryptoEngineOptionsMap, err = parseCryptoEngineOptions(*cryptoEngineOptions)
		if err != nil {
			log.Fatalf("could not parse crypto engine options: %s", err)
		}
		fmt.Printf("Crypto Engines: %v\n", cryptoEngineOptionsMap)
	}

	fmt.Println("========== LAUNCHING AUXILIARY SERVICES ==========")
	fmt.Println(">> Storage Engine")
	pluglableStorageConfig := &config.PluggableStorageEngine{
		LogLevel: config.Trace,
	}

	if *storageEngine == "sqlite" {
		if *sqliteOptions == "" {
			log.Fatalf("sqlite storage engine requires a path to the database file. None provided. Exiting...")
		}

		fmt.Printf("using sqlite storage engine: %s", *sqliteOptions)
		pluglableStorageConfig.Provider = config.SQLite
		pluglableStorageConfig.SQLite = config.SQLitePSEConfig{
			DatabasePath: *sqliteOptions,
		}
	} else if *storageEngine == "couchdb" {
		fmt.Println(" 	launching docker: CouchDB ...")
		cCleanup, couchConfig, err := couchdb_test.RunCouchDBDocker()
		if err != nil {
			log.Fatalf("could not launch CouchDB: %s", err)
		}

		pluglableStorageConfig.Provider = config.CouchDB
		pluglableStorageConfig.CouchDB = *couchConfig
		cleanupMap["postgres"] = cCleanup

	} else {
		fmt.Println(" 	launching docker: Postgres ...")

		pCleanup, postgresStorageConfig, err := postgres_test.RunPostgresDocker([]string{"ca", "alerts", "dmsmanager", "devicemanager", "cloudproxy"})
		if err != nil {
			log.Fatalf("could not launch Postgres: %s", err)
		}

		fmt.Printf(" 		-- postgres port: %d\n", postgresStorageConfig.Port)
		fmt.Printf(" 		-- postgres user: %s\n", postgresStorageConfig.Username)
		fmt.Printf(" 		-- postgres pass: %s\n", postgresStorageConfig.Password)

		pluglableStorageConfig.Provider = config.Postgres
		pluglableStorageConfig.Postgres = *postgresStorageConfig

		cleanupMap["postgres"] = pCleanup
	}

	fmt.Println(">> Crypto Engines")
	cryptoEnginesConfig := config.CryptoEngines{
		LogLevel: config.Info,
	}

	if _, ok := cryptoEngineOptionsMap[GolangFS]; ok {
		cryptoEnginesConfig.DefaultEngine = "golangfs-1"
		cryptoEnginesConfig.GolangProvider = []config.GolangEngineConfig{
			{
				ID:               "golangfs-1",
				Metadata:         make(map[string]interface{}),
				StorageDirectory: "/tmp/gotest",
			},
		}
	}

	if _, ok := cryptoEngineOptionsMap[Vault]; ok {
		fmt.Println("	launching docker: Hashicorp Vault ...")
		var err error
		vCleanup, vaultConfig, rootToken, err := keyvaultkv2_test.RunHashicorpVaultDocker()
		if err != nil {
			log.Fatalf("could not launch Hashicorp Vault: %s", err)
		}

		fmt.Printf(" 		-- vault port: %d\n", vaultConfig.Port)
		fmt.Printf(" 		-- vault root token: %s\n", rootToken)

		cryptoEnginesConfig.DefaultEngine = "dockertest-hcpvault-kvv2"
		cryptoEnginesConfig.HashicorpVaultKV2Provider = []config.HashicorpVaultCryptoEngineConfig{
			{
				HashicorpVaultSDK: *vaultConfig,
				ID:                "dockertest-hcpvault-kvv2",
				Metadata:          make(map[string]interface{}),
			},
		}

		cleanupMap["Hashicorp Vault"] = vCleanup
	}

	_, awsSecretsEnabled := cryptoEngineOptionsMap[AwsSecretsManager]
	_, awsKmsEnabled := cryptoEngineOptionsMap[AwsSecretsManager]
	if awsSecretsEnabled || awsKmsEnabled {
		var err error
		fmt.Println("	launching docker: AWS Platform (Secrets Manager + KMS) ...")
		awsCleanup, awsCfg, err := awskmssm_test.RunAWSEmulationLocalStackDocker()
		if err != nil {
			log.Fatalf("could not launch AWS Platform: %s", err)
		}

		if awsKmsEnabled {
			cryptoEnginesConfig.DefaultEngine = "dockertest-localstack-kms"
			cryptoEnginesConfig.AWSKMSProvider = []config.AWSCryptoEngine{
				{
					AWSSDKConfig: *awsCfg,
					ID:           "dockertest-localstack-kms",
					Metadata:     make(map[string]interface{}),
				},
			}
		}

		if _, ok := cryptoEngineOptionsMap[AwsSecretsManager]; ok {
			cryptoEnginesConfig.DefaultEngine = "dockertest-localstack-smngr"
			cryptoEnginesConfig.AWSSecretsManagerProvider = []config.AWSCryptoEngine{
				{
					AWSSDKConfig: *awsCfg,
					ID:           "dockertest-localstack-smngr",
					Metadata:     make(map[string]interface{}),
				},
			}
		}

		cleanupMap["AWS - LocalStack"] = awsCleanup
	}

	hsmModulePath := *hsmModule
	if _, ok := cryptoEngineOptionsMap[Pkcs11]; ok && hsmModulePath != "" {
		fmt.Println("	launching docker: SoftHSM ...")
		var err error
		softhsmCleanup, pkcs11Cfg, err := softhsmv2_test.RunSoftHsmV2Docker(hsmModulePath)
		if err != nil {
			log.Fatalf("could not launch SoftHSM: %s", err)
		}

		cryptoEnginesConfig.PKCS11Provider = []config.PKCS11EngineConfig{
			{
				PKCS11Config: *pkcs11Cfg,
				ID:           "softhsm-test",
				Metadata:     make(map[string]interface{}),
			},
		}

		cleanupMap["Soft HSM"] = softhsmCleanup
	}

	fmt.Println(">> Async Messaging Engine")
	eventBus := config.EventBusEngine{
		LogLevel: config.Info,
		Enabled:  false,
	}

	if !*disableEventBus {
		fmt.Println("	launching docker: RabbitMQ ...")
		var err error
		rmqCleanup, rmqConfig, adminPort, err := rabbitmq_test.RunRabbitMQDocker()
		if err != nil {
			log.Fatalf("could not launch RabbitMQ: %s", err)
		}
		fmt.Printf(" 		-- rabbitmq UI port: %d\n", adminPort)
		fmt.Printf(" 		-- rabbitmq amqp port: %d\n", rmqConfig.Port)
		fmt.Printf(" 		-- rabbitmq user: %s\n", rmqConfig.BasicAuth.Username)
		fmt.Printf(" 		-- rabbitmq pass: %s\n", rmqConfig.BasicAuth.Password)

		eventBus.Enabled = true
		eventBus.Provider = config.Amqp
		eventBus.Amqp = *rmqConfig

		cleanupMap["RabbitMQ"] = rmqCleanup
	}

	fmt.Println("========== READY TO LAUNCH MONOLITHIC PKI ==========")

	cleanup := func() {
		fmt.Println("========== CLEANING UP ==========")
		svcCleanup := func(svcName string, cleaner func() error) {
			fmt.Printf("Cleaning %s ...\n", svcName)
			err := cleaner()
			if err != nil {
				fmt.Printf("could not cleanup %s: %s\n", svcName, err)
			}
		}

		for svcName, cleaner := range cleanupMap {
			svcCleanup(svcName, cleaner)
		}
	}

	//capture future panics
	defer func() {
		if err := recover(); err != nil {
			printWColor(" !! Panic !! ", color.FgWhite, color.BgRed)
			fmt.Println(err)
			fmt.Println()

			printWColor("cleaning up", color.FgRed, color.BgBlack)
			fmt.Println()
		}
	}()

	//capture CTRL+C
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			// sig is a ^C, handle it
			fmt.Println("ctrl+c triggered. Cleaning up")
			cleanup()
			os.Exit(0)
		}
	}()

	conf := config.MonolithicConfig{
		Logs:               config.BaseConfigLogging{Level: config.Debug},
		SubscriberEventBus: eventBus,
		PublisherEventBus:  eventBus,
		Domain:             "dev.lamassu.test",
		GatewayPort:        8443,
		AssemblyMode:       config.Http,
		CryptoEngines:      cryptoEnginesConfig,
		CryptoMonitoring: config.CryptoMonitoring{
			Enabled:   !*disableMonitor,
			Frequency: "* * * * *",
		},
		Storage: *pluglableStorageConfig,
		AWSIoTManager: config.MonolithicAWSIoTManagerConfig{
			Enabled:     *awsIoTManager,
			ConnectorID: fmt.Sprintf("aws.%s", *awsIoTManagerID),
			AWSSDKConfig: config.AWSSDKConfig{
				AccessKeyID:     *awsIoTManagerUser,
				SecretAccessKey: config.Password(*awsIoTManagerPass),
				Region:          *awsIoTManagerRegion,
			},
		},
	}

	_, err := monolithic.RunMonolithicLamassuPKI(conf)
	if err != nil {
		panic(err)
	}

	fmt.Print(lamassuLogo)
	fmt.Print(readyToPKI)

	http.DefaultClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	time.Sleep(3 * time.Second)
	caCli := clients.NewHttpCAClient(http.DefaultClient, fmt.Sprintf("https://127.0.0.1:%d/api/ca", conf.GatewayPort))
	engines, err := caCli.GetCryptoEngineProvider(context.Background())
	if err != nil {
		panic(err)
	}

	fmt.Println("==================== Available Crypto Engines ==========================")
	for _, engine := range engines {
		fmt.Println(engine.ID)
	}
	fmt.Println("========================================================================")

	forever := make(chan struct{})
	<-forever

}

func parseCryptoEngineOptions(options string) (map[CryptoEngineOption]struct{}, error) {
	if options == "" {
		return nil, nil
	}
	// lowercase the options
	options = strings.ToLower(options)

	opts := make(map[CryptoEngineOption]struct{})
	for _, opt := range strings.Split(options, ",") {
		switch CryptoEngineOption(opt) {
		case AwsSecretsManager, AwsKms, Vault, Pkcs11, GolangFS:
			opts[CryptoEngineOption(opt)] = struct{}{}
		default:
			return nil, fmt.Errorf("invalid crypto engine option: %s", opt)
		}
	}
	return opts, nil
}

func printWColor(str string, fg, bg color.Attribute) {
	color.Set(fg)
	color.Set(bg)
	fmt.Println(str)
	color.Unset()
}
