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
	laws "github.com/lamassuiot/lamassuiot/v3/aws"
	"github.com/lamassuiot/lamassuiot/v3/backend/pkg/config"
	cconfig "github.com/lamassuiot/lamassuiot/v3/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v3/engines/crypto/aws"
	fscengine "github.com/lamassuiot/lamassuiot/v3/engines/crypto/filesystem"
	pconfig "github.com/lamassuiot/lamassuiot/v3/engines/crypto/pkcs11/config"
	softhsmv2_test "github.com/lamassuiot/lamassuiot/v3/engines/crypto/pkcs11/test"
	vconfig "github.com/lamassuiot/lamassuiot/v3/engines/crypto/vaultkv2/config"
	keyvaultkv2_test "github.com/lamassuiot/lamassuiot/v3/engines/crypto/vaultkv2/docker"
	eventbus_amqp "github.com/lamassuiot/lamassuiot/v3/engines/eventbus/amqp/config"
	rabbitmq_test "github.com/lamassuiot/lamassuiot/v3/engines/eventbus/amqp/test"
	postgres_test "github.com/lamassuiot/lamassuiot/v3/engines/storage/postgres/test"
	"github.com/lamassuiot/lamassuiot/v3/monolithic/pkg"
	"github.com/lamassuiot/lamassuiot/v3/sdk"
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
	awsIoTManagerAKID := flag.String("awsiot-keyid", "", "AWS IoT Manager AccessKeyID")
	awsIoTManagerSAK := flag.String("awsiot-keysecret", "", "AWS IoT Manager SecretAccessKey")
	awsIoTManagerST := flag.String("awsiot-sessiontoken", "", "AWS IoT Manager SessionToken")
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
		fmt.Printf("AWS IoT Manager AccessKey: %s\n", *awsIoTManagerAKID)
		fmt.Printf("AWS IoT Manager SecretAccessKey: %s\n", *awsIoTManagerSAK)
		fmt.Printf("AWS IoT Manager SessionToken: %s\n", *awsIoTManagerST)
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
	var postgresStorageConfig *cconfig.PostgresPSEConfig
	if *sqliteOptions == "" {
		fmt.Println(">> launching docker: Postgres ...")
		var err error
		pCleanup, postgresStorageConfig, err = postgres_test.RunPostgresDocker(map[string]string{
			"ca":            "",
			"alerts":        "",
			"dmsmanager":    "",
			"devicemanager": "",
		})
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
	vaultConfig := &vconfig.HashicorpVaultSDK{}
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
	awsCfg := &laws.AWSSDKConfig{}
	if awsSecretsEnabled || awsKmsEnabled {
		var err error
		fmt.Println(">> launching docker: AWS Platform (Secrets Manager + KMS) ...")
		awsCleanup, awsCfg, err = laws.RunAWSEmulationLocalStackDocker()
		if err != nil {
			log.Fatalf("could not launch AWS Platform: %s", err)
		}
	}

	hsmModulePath := *hsmModule
	var softhsmCleanup func() error
	var pkcs11Cfg *pconfig.PKCS11Config
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
	rmqConfig := &eventbus_amqp.AMQPConnection{}
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

	eventBusConfig, _ := cconfig.EncodeStruct(rmqConfig)
	eventBus := cconfig.EventBusEngine{
		LogLevel: cconfig.Trace,
		Enabled:  false,
		Provider: cconfig.Amqp,
		Config:   eventBusConfig,
	}

	if !*disableEventbus {
		eventBus.Enabled = true
	}

	cryptoEnginesConfig := config.CryptoEngines{
		LogLevel: cconfig.Info,
	}

	if _, ok := cryptoengineOptionsMap[Vault]; ok {
		cryptoEnginesConfig.DefaultEngine = "dockertest-hcpvault-kvv2"
		cryptoEnginesConfig.CryptoEngines = append(cryptoEnginesConfig.CryptoEngines, cconfig.CryptoEngine[any]{
			ID:       "dockertest-hcpvault-kvv2",
			Metadata: make(map[string]interface{}),
			Type:     cconfig.HashicorpVaultProvider,
			Config: vconfig.HashicorpVaultCryptoEngineConfig{
				HashicorpVaultSDK: *vaultConfig,
			},
		})
	}

	if _, ok := cryptoengineOptionsMap[AwsKms]; ok {
		cryptoEnginesConfig.DefaultEngine = "dockertest-localstack-kms"
		cryptoEnginesConfig.CryptoEngines = append(cryptoEnginesConfig.CryptoEngines, cconfig.CryptoEngine[any]{
			ID:       "dockertest-localstack-kms",
			Metadata: make(map[string]interface{}),
			Type:     cconfig.AWSKMSProvider,
			Config: aws.AWSCryptoEngine{
				AWSSDKConfig: *awsCfg,
			},
		})
	}

	if _, ok := cryptoengineOptionsMap[AwsSecretsManager]; ok {
		cryptoEnginesConfig.DefaultEngine = "dockertest-localstack-smngr"
		cryptoEnginesConfig.CryptoEngines = append(cryptoEnginesConfig.CryptoEngines, cconfig.CryptoEngine[any]{
			ID:       "dockertest-localstack-smngr",
			Metadata: make(map[string]interface{}),
			Type:     cconfig.AWSSecretsManagerProvider,
			Config: aws.AWSCryptoEngine{
				AWSSDKConfig: *awsCfg,
			},
		})
	}

	if _, ok := cryptoengineOptionsMap[GolangFS]; ok {
		cryptoEnginesConfig.DefaultEngine = "golangfs-1"
		cryptoEnginesConfig.CryptoEngines = append(cryptoEnginesConfig.CryptoEngines, cconfig.CryptoEngine[any]{
			ID:       "golangfs-1",
			Metadata: make(map[string]interface{}),
			Type:     cconfig.AWSSecretsManagerProvider,
			Config: fscengine.FilesystemEngineConfig{
				StorageDirectory: "/tmp/gotest",
			},
		})
	}

	if _, ok := cryptoengineOptionsMap[Pkcs11]; ok {
		cryptoEnginesConfig.DefaultEngine = "pkcs11-1"
		cryptoEnginesConfig.CryptoEngines = append(cryptoEnginesConfig.CryptoEngines, cconfig.CryptoEngine[any]{
			ID:       "pkcs11-1",
			Metadata: make(map[string]interface{}),
			Type:     cconfig.AWSSecretsManagerProvider,
			Config: pconfig.PKCS11EngineConfig{
				PKCS11Config: *pkcs11Cfg,
			},
		})
	}

	pluglableStorageConfig := &cconfig.PluggableStorageEngine{
		LogLevel: cconfig.Trace,
	}
	if *sqliteOptions != "" {
		pluglableStorageConfig.Provider = cconfig.SQLite
		pluglableStorageConfig.SQLite = cconfig.SQLitePSEConfig{
			DatabasePath: *sqliteOptions,
		}
	} else {
		pluglableStorageConfig.Provider = cconfig.Postgres
		pluglableStorageConfig.Postgres = *postgresStorageConfig
	}

	conf := pkg.MonolithicConfig{
		Logs:               cconfig.Logging{Level: cconfig.Debug},
		SubscriberEventBus: eventBus,
		PublisherEventBus:  eventBus,
		Domain:             "dev.lamassu.test",
		GatewayPort:        8443,
		AssemblyMode:       pkg.Http,
		CryptoEngines:      cryptoEnginesConfig.CryptoEngines,
		CryptoMonitoring: cconfig.MonitoringJob{
			Enabled:   *disableMonitor,
			Frequency: "* * * * *",
		},
		Storage: *pluglableStorageConfig,
		AWSIoTManager: pkg.MonolithicAWSIoTManagerConfig{
			Enabled:     *awsIoTManager,
			ConnectorID: fmt.Sprintf("aws.%s", *awsIoTManagerID),
			AWSSDKConfig: laws.AWSSDKConfig{
				AWSAuthenticationMethod: laws.Static,
				AccessKeyID:             *awsIoTManagerAKID,
				SecretAccessKey:         cconfig.Password(*awsIoTManagerSAK),
				SessionToken:            cconfig.Password(*awsIoTManagerST),
				Region:                  *awsIoTManagerRegion,
			},
		},
	}

	_, err := pkg.RunMonolithicLamassuPKI(conf)
	if err != nil {
		fmt.Println("could not start monolithic PKI. Shuting down: ", err)
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
	caCli := sdk.NewHttpCAClient(http.DefaultClient, fmt.Sprintf("https://127.0.0.1:%d/api/ca", conf.GatewayPort))
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
