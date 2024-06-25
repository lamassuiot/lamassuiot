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
	cryptoengineOptions := flag.String("cryptoengines", "golangfs", ", separated list of crypto engines to enable ['aws-secrets','aws-kms','vault','pkcs11','golangfs']")
	sqliteOptions := flag.String("sqlite", "", "set path to sqlite database to enable sqlite storage engine")
	disableMonitor := flag.Bool("disable-monitor", false, "disable crypto monitoring")
	disableEventbus := flag.Bool("disable-eventbus", false, "disable eventbus")
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

	// By default, all crypto engines are enabled
	cryptoengineOptionsMap := map[CryptoEngineOption]struct{}{
		AwsSecretsManager: {},
		AwsKms:            {},
		Vault:             {},
		Pkcs11:            {},
		GolangFS:          {},
	}

	if (*cryptoengineOptions) != "" {
		var err error
		cryptoengineOptionsMap, err = parseCryptoEngineOptions(*cryptoengineOptions)
		if err != nil {
			log.Fatalf("could not parse crypto engine options: %s", err)
		}
		fmt.Printf("Crypto Engines: %v\n", cryptoengineOptionsMap)
	}

	fmt.Println("========== LAUNCHING AUXILIARY SERVICES ==========")
	fmt.Println("Storage Engine")
	pCleanup := func() error { return nil }
	var postgresStorageConfig *config.PostgresPSEConfig
	if *sqliteOptions == "" {
		fmt.Println(">> launching docker: Postgres ...")
		var err error
		pCleanup, postgresStorageConfig, err = postgres_test.RunPostgresDocker([]string{"ca", "alerts", "dmsmanager", "devicemanager", "cloudproxy"})
		if err != nil {
			log.Fatalf("could not launch Postgres: %s", err)
		}

		fmt.Printf(" 	-- postgres port: %d\n", postgresStorageConfig.Port)
		fmt.Printf(" 	-- postgres user: %s\n", postgresStorageConfig.Username)
		fmt.Printf(" 	-- postgres pass: %s\n", postgresStorageConfig.Password)
	} else {
		fmt.Printf(">> using sqlite storage engine: %s", *sqliteOptions)
	}

	fmt.Println("Crypto Engines")
	vCleanup := func() error { return nil }
	vaultConfig := &config.HashicorpVaultSDK{}
	rootToken := ""
	if _, ok := cryptoengineOptionsMap[Vault]; ok {
		fmt.Println(">> launching docker: Hashicorp Vault ...")
		var err error
		vCleanup, vaultConfig, rootToken, err = keyvaultkv2_test.RunHashicorpVaultDocker()
		if err != nil {
			log.Fatalf("could not launch Hashicorp Vault: %s", err)
		}
		fmt.Printf(" 	-- vault port: %d\n", vaultConfig.Port)
		fmt.Printf(" 	-- vault root token: %s\n", rootToken)
	}

	_, awsSecretsEnabled := cryptoengineOptionsMap[AwsSecretsManager]
	_, awsKmsEnabled := cryptoengineOptionsMap[AwsSecretsManager]
	awsCleanup := func() error { return nil }
	awsCfg := &config.AWSSDKConfig{}
	if awsSecretsEnabled || awsKmsEnabled {
		var err error
		fmt.Println(">> launching docker: AWS Platform (Secrets Manager + KMS) ...")
		awsCleanup, awsCfg, err = awskmssm_test.RunAWSEmulationLocalStackDocker()
		if err != nil {
			log.Fatalf("could not launch AWS Platform: %s", err)
		}
	}

	hsmModulePath := *hsmModule
	var softhsmCleanup func() error
	var pkcs11Cfg *config.PKCS11Config
	if _, ok := cryptoengineOptionsMap[Pkcs11]; ok && hsmModulePath != "" {
		fmt.Println(">> launching docker: SoftHSM ...")
		var err error
		softhsmCleanup, pkcs11Cfg, err = softhsmv2_test.RunSoftHsmV2Docker(hsmModulePath)
		if err != nil {
			log.Fatalf("could not launch SoftHSM: %s", err)
		}
	}

	fmt.Println("Async Messaging Engine")
	rmqCleanup := func() error { return nil }
	rmqConfig := &config.AMQPConnection{}
	adminPort := 0
	if !*disableEventbus {
		fmt.Println(">> launching docker: RabbitMQ ...")
		var err error
		rmqCleanup, rmqConfig, adminPort, err = rabbitmq_test.RunRabbitMQDocker()
		if err != nil {
			log.Fatalf("could not launch RabbitMQ: %s", err)
		}
		fmt.Printf(" 	-- rabbitmq UI port: %d\n", adminPort)
		fmt.Printf(" 	-- rabbitmq amqp port: %d\n", rmqConfig.Port)
		fmt.Printf(" 	-- rabbitmq user: %s\n", rmqConfig.BasicAuth.Username)
		fmt.Printf(" 	-- rabbitmq pass: %s\n", rmqConfig.BasicAuth.Password)
	}

	fmt.Println("========== READY TO LAUNCH MONOLITHIC PKI ==========")

	cleanup := func() {
		fmt.Println("========== CLEANING UP ==========")
		svcCleanup := func(svcName string, cleaner func() error) {
			fmt.Printf(">> Cleaning %s ...\n", svcName)
			err := cleaner()
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

	eventBus := config.EventBusEngine{
		LogLevel: config.Trace,
		Enabled:  false,
		Provider: config.Amqp,
		Amqp:     *rmqConfig,
	}
	if !*disableEventbus {
		eventBus.Enabled = true
	}

	cryptoEnginesConfig := config.CryptoEngines{
		LogLevel: config.Info,
	}

	if _, ok := cryptoengineOptionsMap[Vault]; ok {
		cryptoEnginesConfig.DefaultEngine = "dockertest-hcpvault-kvv2"
		cryptoEnginesConfig.GolangHashicorpVaultKV2Provider = []config.HashicorpVaultCryptoEngineConfig{
			{
				HashicorpVaultSDK: *vaultConfig,
				ID:                "dockertest-hcpvault-kvv2",
				Metadata:          make(map[string]interface{}),
			},
		}
	}

	if _, ok := cryptoengineOptionsMap[AwsKms]; ok {
		cryptoEnginesConfig.DefaultEngine = "dockertest-localstack-kms"
		cryptoEnginesConfig.AWSKMSProvider = []config.AWSCryptoEngine{
			{
				AWSSDKConfig: *awsCfg,
				ID:           "dockertest-localstack-kms",
				Metadata:     make(map[string]interface{}),
			},
		}
	}

	if _, ok := cryptoengineOptionsMap[AwsSecretsManager]; ok {
		cryptoEnginesConfig.DefaultEngine = "dockertest-localstack-smngr"
		cryptoEnginesConfig.GolangAWSSecretsManagerProvider = []config.AWSCryptoEngine{
			{
				AWSSDKConfig: *awsCfg,
				ID:           "dockertest-localstack-smngr",
				Metadata:     make(map[string]interface{}),
			},
		}
	}

	if _, ok := cryptoengineOptionsMap[GolangFS]; ok {
		cryptoEnginesConfig.DefaultEngine = "golangfs-1"
		cryptoEnginesConfig.GolangFilesystemProvider = []config.GolangFilesystemEngineConfig{
			{
				ID:               "golangfs-1",
				Metadata:         make(map[string]interface{}),
				StorageDirectory: "/tmp/gotest",
			},
		}
	}

	pluglableStorageConfig := &config.PluggableStorageEngine{
		LogLevel: config.Trace,
	}
	if *sqliteOptions != "" {
		pluglableStorageConfig.Provider = config.SQLite
		pluglableStorageConfig.SQLite = config.SQLitePSEConfig{
			DatabasePath: *sqliteOptions,
		}
	} else {
		pluglableStorageConfig.Provider = config.Postgres
		pluglableStorageConfig.Postgres = *postgresStorageConfig
	}

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

	if hsmModulePath != "" {
		conf.CryptoEngines.PKCS11Provider = append(conf.CryptoEngines.PKCS11Provider, config.PKCS11EngineConfig{
			PKCS11Config: *pkcs11Cfg,
			ID:           "softhsm-test",
			Metadata:     make(map[string]interface{}),
		})
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
