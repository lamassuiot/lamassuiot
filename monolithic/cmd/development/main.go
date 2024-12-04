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
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg"
	"github.com/lamassuiot/lamassuiot/sdk/v3"
	laws "github.com/lamassuiot/lamassuiot/shared/aws/v3"
	"github.com/lamassuiot/lamassuiot/shared/subsystems/v3/pkg/test/subsystems"
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
	Filesystem        CryptoEngineOption = "filesystem"
)

func main() {
	hsmModule := flag.String("hsm-module-path", "", "enable HSM support")

	awsIoTManager := flag.Bool("awsiot", false, "enable AWS IoT Manager")
	awsIoTManagerAKID := flag.String("awsiot-keyid", "", "AWS IoT Manager AccessKeyID")
	awsIoTManagerSAK := flag.String("awsiot-keysecret", "", "AWS IoT Manager SecretAccessKey")
	awsIoTManagerST := flag.String("awsiot-sessiontoken", "", "AWS IoT Manager SessionToken")
	awsIoTManagerRegion := flag.String("awsiot-region", "eu-west-1", "AWS IoT Manager Region")
	awsIoTManagerID := flag.String("awsiot-id", "", "AWS IoT Manager ConnectorID")
	cryptoengineOptions := flag.String("cryptoengines", "filesystem", ", separated list of crypto engines to enable ['aws-secrets','aws-kms','vault','pkcs11','filesystem']")
	sqliteOptions := flag.String("sqlite", "", "set path to sqlite database to enable sqlite storage engine")
	disableMonitor := flag.Bool("disable-monitor", false, "disable crypto monitoring")
	disableEventbus := flag.Bool("disable-eventbus", false, "disable eventbus")
	useAwsEventbus := flag.Bool("use-aws-eventbus", false, "use AWS Eventbus")
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
		Filesystem:        {},
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
	pCleanup := func() { /* do nothing */ }
	var postgresStorageConfig cconfig.PluggableStorageEngine
	if *sqliteOptions == "" {
		fmt.Println(">> launching docker: Postgres ...")
		posgresSubsystem := subsystems.GetSubsystemBuilder[subsystems.StorageSubsystem](subsystems.Postgres)
		posgresSubsystem.Prepare([]string{"ca", "alerts", "dmsmanager", "devicemanager"})
		backend, err := posgresSubsystem.Run()
		if err != nil {
			log.Fatalf("could not launch Postgres: %s", err)
		}

		pCleanup = backend.AfterSuite
		postgresStorageConfig = backend.Config.(cconfig.PluggableStorageEngine)

		fmt.Printf(" 	-- postgres port: %d\n", postgresStorageConfig.Config["port"].(int))
		fmt.Printf(" 	-- postgres user: %s\n", postgresStorageConfig.Config["username"].(string))
		fmt.Printf(" 	-- postgres pass: %s\n", postgresStorageConfig.Config["password"].(cconfig.Password))
	} else {
		fmt.Printf(">> using sqlite storage engine: %s", *sqliteOptions)
	}

	fmt.Println("Crypto Engines")
	vCleanup := func() { /* do nothing */ }

	var vaultCryptoEngine cconfig.CryptoEngineConfig
	rootToken := ""
	if _, ok := cryptoengineOptionsMap[Vault]; ok {
		fmt.Println(">> launching docker: Hashicorp Vault ...")
		vaultSubsystem, err := subsystems.GetSubsystemBuilder[subsystems.Subsystem](subsystems.Vault).Run()
		if err != nil {
			log.Fatalf("could not launch Hashicorp Vault: %s", err)
		}

		vCleanup = vaultSubsystem.AfterSuite
		vaultCryptoEngine := vaultSubsystem.Config.(cconfig.CryptoEngineConfig)

		port := (vaultCryptoEngine.Config)["port"].(int)
		rootToken = (*vaultSubsystem.Extra)["rootToken"].(string)

		fmt.Printf(" 	-- vault port: %d\n", port)
		fmt.Printf(" 	-- vault root token: %s\n", rootToken)
	}

	_, awsSecretsEnabled := cryptoengineOptionsMap[AwsSecretsManager]
	_, awsKmsEnabled := cryptoengineOptionsMap[AwsKms]
	awsCleanup := func() { /* do nothing */ }
	var awsBaseCryptoEngine cconfig.CryptoEngineConfig
	if awsSecretsEnabled || awsKmsEnabled {
		fmt.Println(">> launching docker: AWS Platform (Secrets Manager + KMS) ...")
		awsSubsystem, err := subsystems.GetSubsystemBuilder[subsystems.Subsystem](subsystems.Aws).Run()
		if err != nil {
			log.Fatalf("could not launch AWS Platform: %s", err)
		}

		awsCleanup = awsSubsystem.AfterSuite
		awsBaseCryptoEngine = awsSubsystem.Config.(cconfig.CryptoEngineConfig)
	}

	hsmModulePath := *hsmModule
	var softhsmCleanup func()
	var pkcs11Cfg cconfig.CryptoEngineConfig
	if _, ok := cryptoengineOptionsMap[Pkcs11]; ok && hsmModulePath != "" {
		fmt.Println(">> launching docker: SoftHSM ...")
		pkcs11SubsystemBuilder := subsystems.GetSubsystemBuilder[subsystems.ParametrizedSubsystem](subsystems.Pkcs11)
		pkcs11SubsystemBuilder.Prepare(map[string]interface{}{"hsmModulePath": hsmModulePath})
		pkcs11Subsystem, err := pkcs11SubsystemBuilder.Run()
		if err != nil {
			log.Fatalf("could not launch SoftHSM: %s", err)
		}
		softhsmCleanup = pkcs11Subsystem.AfterSuite

		pkcs11Cfg = pkcs11Subsystem.Config.(cconfig.CryptoEngineConfig)

	}

	fmt.Println("Async Messaging Engine")
	rmqCleanup := func() { /* do nothing */ }
	adminPort := 0
	eventBus := cconfig.EventBusEngine{
		LogLevel: cconfig.Trace,
		Enabled:  false,
		Provider: cconfig.Amqp,
		Config:   make(map[string]interface{}),
	}

	if !*disableEventbus && !*useAwsEventbus {
		fmt.Println(">> launching docker: RabbitMQ ...")
		rabbitmqSubsystem, err := subsystems.GetSubsystemBuilder[subsystems.Subsystem](subsystems.RabbitMQ).Run()
		if err != nil {
			log.Fatalf("could not launch RabbitMQ: %s", err)
		}

		rmqCleanup = rabbitmqSubsystem.AfterSuite

		eventBus = rabbitmqSubsystem.Config.(cconfig.EventBusEngine)

		adminPort = (*rabbitmqSubsystem.Extra)["adminPort"].(int)
		basicAuth := eventBus.Config["basic_auth"].(map[string]interface{})

		fmt.Printf(" 	-- rabbitmq UI port: %d\n", adminPort)
		fmt.Printf(" 	-- rabbitmq amqp port: %d\n", eventBus.Config["port"].(int))
		fmt.Printf(" 	-- rabbitmq user: %s\n", basicAuth["username"].(string))
		fmt.Printf(" 	-- rabbitmq pass: %s\n", basicAuth["password"].(cconfig.Password))
	}

	if !*disableEventbus && *useAwsEventbus {
		fmt.Println(">> using AWS Eventbus")
		internalConfig := awsBaseCryptoEngine.Config

		eventBus = cconfig.EventBusEngine{
			LogLevel: cconfig.Trace,
			Enabled:  true,
			Provider: cconfig.AWSSqsSns,
			Config:   internalConfig,
		}
	}

	fmt.Println("========== READY TO LAUNCH MONOLITHIC PKI ==========")

	cleanup := func() {
		fmt.Println("========== CLEANING UP ==========")
		svcCleanup := func(svcName string, cleaner func()) {
			fmt.Printf(">> Cleaning %s ...\n", svcName)
			cleaner()
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

	cryptoEnginesConfig := config.CryptoEngines{
		LogLevel: cconfig.Info,
	}

	cryptoEngines := []cconfig.CryptoEngineConfig{}

	if _, ok := cryptoengineOptionsMap[Vault]; ok {
		vaultCryptoEngine.ID = "dockertest-hcpvault-kvv2"
		cryptoEnginesConfig.DefaultEngine = vaultCryptoEngine.ID
		cryptoEngines = append(cryptoEngines, vaultCryptoEngine)
	}

	if _, ok := cryptoengineOptionsMap[AwsKms]; ok {
		kmsCryptoEngine := cconfig.CryptoEngineConfig{
			ID:       "dockertest-localstack-kms",
			Metadata: make(map[string]interface{}),
			Type:     cconfig.AWSKMSProvider,
			Config:   awsBaseCryptoEngine.Config,
		}
		cryptoEnginesConfig.DefaultEngine = kmsCryptoEngine.ID
		cryptoEngines = append(cryptoEngines, kmsCryptoEngine)
	}

	if _, ok := cryptoengineOptionsMap[AwsSecretsManager]; ok {
		secretsManagerCryptoEngine := cconfig.CryptoEngineConfig{
			ID:       "dockertest-localstack-smngr",
			Metadata: make(map[string]interface{}),
			Type:     cconfig.AWSSecretsManagerProvider,
			Config:   awsBaseCryptoEngine.Config,
		}
		cryptoEnginesConfig.DefaultEngine = secretsManagerCryptoEngine.ID
		cryptoEngines = append(cryptoEngines, secretsManagerCryptoEngine)
	}

	if _, ok := cryptoengineOptionsMap[Filesystem]; ok {
		cryptoEngines = append(cryptoEngines, cconfig.CryptoEngineConfig{
			ID:       "filesystem-1",
			Metadata: make(map[string]interface{}),
			Type:     cconfig.FilesystemProvider,
			Config: map[string]interface{}{
				"storage_directory": "/tmp/gotest",
			},
		})
		cryptoEnginesConfig.DefaultEngine = "filesystem-1"
	}

	if _, ok := cryptoengineOptionsMap[Pkcs11]; ok {
		pkcs11Cfg.ID = "pkcs11-1"
		cryptoEnginesConfig.DefaultEngine = pkcs11Cfg.ID
		cryptoEngines = append(cryptoEngines, pkcs11Cfg)
	}

	cryptoEnginesConfig.CryptoEngines = cryptoEngines

	pluglableStorageConfig := &cconfig.PluggableStorageEngine{
		LogLevel: cconfig.Trace,
	}
	if *sqliteOptions != "" {
		pluglableStorageConfig.Provider = cconfig.SQLite
		pluglableStorageConfig.Config = map[string]interface{}{
			"databasePath": *sqliteOptions,
		}
	} else {
		pluglableStorageConfig = &postgresStorageConfig
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
		case AwsSecretsManager, AwsKms, Vault, Pkcs11, Filesystem:
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
