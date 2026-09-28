package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/devstorage"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/eventbus/inmemory"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/sampledata"
	"github.com/lamassuiot/lamassuiot/sdk/v3"
	laws "github.com/lamassuiot/lamassuiot/shared/aws/v3"
	"github.com/lamassuiot/lamassuiot/shared/subsystems/v3/pkg/test/dockerrunner"
	"github.com/lamassuiot/lamassuiot/shared/subsystems/v3/pkg/test/subsystems"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
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
	opts, err := parseOptions(os.Args[1:], os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid options: %s\n", err)
		os.Exit(2)
	}

	fmt.Println("===================== FLAGS ======================")

	fmt.Printf("AWS IoT Manager Enabled: %v\n", opts.awsIoTManager)
	fmt.Printf("Sample Data Enabled: %v\n", opts.sampleData)
	if opts.awsIoTManager {
		ai := opts.awsIoTManagerID
		fmt.Printf("AWS IoT Manager ConnectorID: %s\n", ai)
		fmt.Printf("AWS IoT Manager AccessKey: %s\n", opts.awsIoTManagerAKID)
		fmt.Printf("AWS IoT Manager SecretAccessKey: %s\n", opts.awsIoTManagerSAK)
		fmt.Printf("AWS IoT Manager SessionToken: %s\n", opts.awsIoTManagerST)
		fmt.Printf("AWS IoT Manager Region: %s\n", opts.awsIoTManagerRegion)
	}

	if opts.hsmModule != "" {
		fmt.Printf("HSM - PKCS11 Module Driver: %s\n", opts.hsmModule)
	}

	// By default, all crypto engines are enabled
	cryptoengineOptionsMap := map[CryptoEngineOption]struct{}{
		AwsSecretsManager: {},
		AwsKms:            {},
		Vault:             {},
		Pkcs11:            {},
		Filesystem:        {},
	}

	if opts.cryptoengineOptions != "" {
		var err error
		cryptoengineOptionsMap, err = parseCryptoEngineOptions(opts.cryptoengineOptions)
		if err != nil {
			log.Fatalf("could not parse crypto engine options: %s", err)
		}
		fmt.Printf("Crypto Engines: %v\n", cryptoengineOptionsMap)
	}
	cleanup := func() {
		fmt.Println("========== CLEANING UP ==========")

		cli, err := docker.NewClientFromEnv()
		if err != nil {
			fmt.Println("could not create docker client: ", err)
			return
		}

		// List all containers (running or not)
		containers, err := cli.ListContainers(docker.ListContainersOptions{
			All: true,
		})
		if err != nil {
			log.Printf("Could not list containers during cleanup: %s", err)
			return
		}

		// Label to match
		targetLabel := "group"
		targetValue := "lamassuiot-monolithic"

		for _, container := range containers {
			labels := container.Labels
			if val, ok := labels[targetLabel]; ok && val == targetValue {
				log.Printf("Found container %s with label %s=%s", container.ID, targetLabel, targetValue)

				// Stop the container
				err := cli.StopContainer(container.ID, 10)
				if err != nil {
					log.Printf("Error stopping container %s: %v", container.ID, err)
				} else {
					log.Printf("Stopped container %s", container.ID)
				}

				// Remove the container
				err = cli.RemoveContainer(docker.RemoveContainerOptions{
					ID:    container.ID,
					Force: true,
				})
				if err != nil {
					log.Printf("Error removing container %s: %v", container.ID, err)
				} else {
					log.Printf("Removed container %s", container.ID)
				}
			}
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

			cleanup()
		}
	}()

	//capture CTRL+C
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for range c {
			// sig is a ^C, handle it
			fmt.Println("ctrl+c triggered. Cleaning up")
			cleanup()
			os.Exit(0)
		}
	}()

	fmt.Println("========== LAUNCHING AUXILIARY SERVICES ==========")

	// Register monolithic-specific engines
	if opts.useInMemoryEventbus {
		inmemory.Register()
	}

	fmt.Println("Storage Engine")
	var storageConfig cconfig.PluggableStorageEngine

	// Solo PostgreSQL: parseOptions rechaza -sqlite (spec 009, P1).
	pg, err := devstorage.Start(context.Background(), devstorage.StartOptions{
		External:     opts.externalPostgres(),
		StandardPort: opts.standardDockerPorts,
	})
	if err != nil {
		log.Fatalf("could not start PostgreSQL: %s", err)
	}
	if pg.Launched {
		fmt.Println(">> launched docker: Postgres")
		fmt.Printf(" 	-- postgres port: %d\n", pg.Admin.Port)
		fmt.Printf(" 	-- postgres admin user: %s\n", pg.Admin.Username)
		fmt.Printf(" 	-- postgres admin pass: %s\n", pg.Admin.Password)
	} else {
		fmt.Printf(">> using external Postgres %s:%d (admin user %s)\n", pg.Admin.Hostname, pg.Admin.Port, pg.Admin.Username)
	}

	storageLogger := chelpers.SetupLogger(cconfig.Info, "Monolithic", "PostgreSQL")
	prepared, err := devstorage.Prepare(context.Background(), storageLogger, pg.Admin)
	if err != nil {
		pg.Cleanup()
		log.Fatalf("could not prepare PostgreSQL: %s", err)
	}
	storageConfig = prepared.Storage
	fmt.Printf(" 	-- services connect as: %s (random password, row level security applies)\n", devstorage.AppRole)
	for _, grant := range prepared.Grants {
		fmt.Printf(" 	-- grant not provided by migrations: %s\n", grant)
	}

	fmt.Println("Crypto Engines")

	var vaultCryptoEngine cconfig.CryptoEngineConfig
	rootToken := ""
	if _, ok := cryptoengineOptionsMap[Vault]; ok {
		fmt.Println(">> launching docker: Hashicorp Vault ...")
		vaultSubsystem, err := subsystems.GetSubsystemBuilder[subsystems.Subsystem](subsystems.Vault).Run(opts.standardDockerPorts)
		if err != nil {
			log.Fatalf("could not launch Hashicorp Vault: %s", err)
		}

		vaultCryptoEngine := vaultSubsystem.Config.(cconfig.CryptoEngineConfig)

		port := (vaultCryptoEngine.Config)["port"].(int)
		rootToken = (*vaultSubsystem.Extra)["rootToken"].(string)

		fmt.Printf(" 	-- vault port: %d\n", port)
		fmt.Printf(" 	-- vault root token: %s\n", rootToken)
	}

	_, awsSecretsEnabled := cryptoengineOptionsMap[AwsSecretsManager]
	_, awsKmsEnabled := cryptoengineOptionsMap[AwsKms]
	var awsBaseCryptoEngine cconfig.CryptoEngineConfig
	if awsSecretsEnabled || awsKmsEnabled {
		fmt.Println(">> launching docker: AWS Platform (Secrets Manager + KMS) ...")
		awsSubsystem, err := subsystems.GetSubsystemBuilder[subsystems.Subsystem](subsystems.Aws).Run(opts.standardDockerPorts)
		if err != nil {
			log.Fatalf("could not launch AWS Platform: %s", err)
		}

		awsBaseCryptoEngine = awsSubsystem.Config.(cconfig.CryptoEngineConfig)
	}

	hsmModulePath := opts.hsmModule
	var pkcs11Cfg cconfig.CryptoEngineConfig
	if _, ok := cryptoengineOptionsMap[Pkcs11]; ok && hsmModulePath != "" {
		fmt.Println(">> launching docker: SoftHSM ...")
		pkcs11SubsystemBuilder := subsystems.GetSubsystemBuilder[subsystems.ParametrizedSubsystem](subsystems.Pkcs11)
		pkcs11SubsystemBuilder.Prepare(map[string]interface{}{"hsmModulePath": hsmModulePath})
		pkcs11Subsystem, err := pkcs11SubsystemBuilder.Run(opts.standardDockerPorts)
		if err != nil {
			log.Fatalf("could not launch SoftHSM: %s", err)
		}

		pkcs11Cfg = pkcs11Subsystem.Config.(cconfig.CryptoEngineConfig)

	}

	fmt.Println("Async Messaging Engine")
	adminPort := 0
	eventBus := cconfig.EventBusEngine{
		LogLevel: cconfig.Trace,
		Enabled:  false,
		Provider: cconfig.Amqp,
		Config:   make(map[string]interface{}),
	}

	dlqEventBus := eventBus

	if !opts.disableEventbus && opts.useInMemoryEventbus {
		fmt.Println(">> using in-memory eventbus (no Docker required) ...")
		eventBus = cconfig.EventBusEngine{
			LogLevel: cconfig.Trace,
			Enabled:  true,
			Provider: "inmemory", // Custom provider for monolithic
			Config:   make(map[string]interface{}),
		}

		dlqEventBus = eventBus
		dlqEventBus.Config = make(map[string]interface{})

		fmt.Println(" 	-- inmemory eventbus: ephemeral GoChannel pub/sub")
	} else if !opts.disableEventbus && !opts.useAwsEventbus {
		fmt.Println(">> launching docker: RabbitMQ ...")
		rabbitmqSubsystem, err := subsystems.GetSubsystemBuilder[subsystems.Subsystem](subsystems.RabbitMQ).Run(opts.standardDockerPorts)
		if err != nil {
			log.Fatalf("could not launch RabbitMQ: %s", err)
		}

		eventBus = rabbitmqSubsystem.Config.(cconfig.EventBusEngine)
		// make a copy for DLQ using deep copy

		adminPort = (*rabbitmqSubsystem.Extra)["adminPort"].(int)
		basicAuth := eventBus.Config["basic_auth"].(map[string]interface{})

		dlqEventBus = eventBus
		dlqEventBus.Config = deepCopy(eventBus.Config)
		dlqEventBus.Config["exchange"] = "lamassu-dlq"

		fmt.Printf(" 	-- rabbitmq UI port: %d\n", adminPort)
		fmt.Printf(" 	-- rabbitmq amqp port: %d\n", eventBus.Config["port"].(int))
		fmt.Printf(" 	-- rabbitmq user: %s\n", basicAuth["username"].(string))
		fmt.Printf(" 	-- rabbitmq pass: %s\n", basicAuth["password"].(cconfig.Password))
	} else if !opts.disableEventbus && opts.useAwsEventbus {
		fmt.Println(">> using AWS Eventbus")
		internalConfig := awsBaseCryptoEngine.Config

		eventBus = cconfig.EventBusEngine{
			LogLevel: cconfig.Trace,
			Enabled:  true,
			Provider: cconfig.AWSSqsSns,
			Config:   internalConfig,
		}
	}

	var uiPort int
	fmt.Printf(">> UI Enabled : %v\n", !opts.disableUI)

	cloudConnectors := "[]"
	if opts.awsIoTManagerID != "" {
		cloudConnectors = fmt.Sprintf("[\"aws.%s\"]", opts.awsIoTManagerID)
	}

	if !opts.disableUI {
		containerCleanup, container, _, err := dockerrunner.RunDocker(dockertest.RunOptions{
			Repository: "ghcr.io/lamassuiot/lamassu-ui", // image
			Tag:        "latest",                        // version
			Env:        []string{"OIDC_ENABLED=false", "UI_FOOTER_ENABLED=false", "LAMASSU_API=https://localhost:8443/api", "CLOUD_CONNECTORS=" + cloudConnectors},
			Labels: map[string]string{
				"group": "lamassuiot-monolithic",
			},
		}, func(hc *docker.HostConfig) {
			hc.AutoRemove = true
		})

		uiPort, _ = strconv.Atoi(container.GetPort("80/tcp"))

		if err != nil {
			containerCleanup()
			log.Fatalf("could not launch ghcr.io/lamassuiot/lamassu-ui:latest: %s", err)
		}
	}

	fmt.Println("========== READY TO LAUNCH MONOLITHIC PKI ==========")

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
		engineId := "filesystem-test-1"
		cryptoEngines = append(cryptoEngines, cconfig.CryptoEngineConfig{
			ID:       engineId,
			Metadata: make(map[string]interface{}),
			Type:     cconfig.FilesystemProvider,
			Config: map[string]interface{}{
				"storage_directory": "/tmp/gotest",
			},
		})
		cryptoEnginesConfig.DefaultEngine = engineId
	}

	if _, ok := cryptoengineOptionsMap[Pkcs11]; ok {
		pkcs11Cfg.ID = "pkcs11-1"
		cryptoEnginesConfig.DefaultEngine = pkcs11Cfg.ID
		cryptoEngines = append(cryptoEngines, pkcs11Cfg)
	}

	cryptoEnginesConfig.CryptoEngines = cryptoEngines

	pluglableStorageConfig := &storageConfig

	conf := pkg.MonolithicConfig{
		OtelConfig: cconfig.OTELConfig{
			Metrics: cconfig.OTELMetricsConfig{Enabled: false},
			Traces:  cconfig.OTELTracesConfig{Enabled: false},
			Logging: cconfig.OTELLoggingConfig{Enabled: false},
		},
		Logs:                  cconfig.Logging{Level: cconfig.Debug},
		UIPort:                uiPort,
		VAStorageDir:          "/tmp/lamassuiot/va",
		SubscriberEventBus:    eventBus,
		SubscriberDLQEventBus: dlqEventBus,
		PublisherEventBus:     eventBus,
		Domains:               []string{"dev.lamassu.test", "localhost"},
		GatewayPortHttps:      8443,
		GatewayPortHttp:       8080,
		AssemblyMode:          pkg.Http,
		CryptoEngines:         cryptoEnginesConfig.CryptoEngines,
		Monitoring: cconfig.MonitoringJob{
			Enabled:   !opts.disableMonitor,
			Frequency: "2m",
		},
		Storage:            *pluglableStorageConfig,
		PopulateSampleData: opts.sampleData,
		AWSIoTManager: pkg.MonolithicAWSIoTManagerConfig{
			Enabled:     opts.awsIoTManager,
			ConnectorID: fmt.Sprintf("aws.%s", opts.awsIoTManagerID),
			AWSSDKConfig: laws.AWSSDKConfig{
				AWSAuthenticationMethod: laws.Static,
				AccessKeyID:             opts.awsIoTManagerAKID,
				SecretAccessKey:         cconfig.Password(opts.awsIoTManagerSAK),
				SessionToken:            cconfig.Password(opts.awsIoTManagerST),
				Region:                  opts.awsIoTManagerRegion,
			},
		},
	}

	_, _, err = pkg.RunMonolithicLamassuPKI(conf)
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
	kmsSDK := sdk.NewHttpKMSClient(http.DefaultClient, fmt.Sprintf("https://127.0.0.1:%d/api/kms", conf.GatewayPortHttps))
	engines, err := kmsSDK.GetCryptoEngineProvider(context.Background())
	if err != nil {
		panic(err)
	}

	fmt.Println("==================== Available Crypto Engines ==========================")
	for _, engine := range engines {
		fmt.Println(engine.ID)
	}
	fmt.Println("========================================================================")

	// Populate sample data if enabled
	if opts.sampleData {
		logger := chelpers.SetupLogger(cconfig.Info, "SampleData", "Populator")
		// Use the internal HTTP ports since services are behind the gateway
		// We'll construct URLs using the gateway
		caServiceURL := fmt.Sprintf("http://127.0.0.1:%d/api/ca", conf.GatewayPortHttp)
		deviceServiceURL := fmt.Sprintf("http://127.0.0.1:%d/api/devmanager", conf.GatewayPortHttp)

		err := sampledata.PopulateSampleData(context.Background(), logger, caServiceURL, deviceServiceURL)
		if err != nil {
			fmt.Printf("Warning: Failed to populate sample data: %v\n", err)
		}
	}

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

func deepCopy(src map[string]interface{}) map[string]interface{} {
	if src == nil {
		return nil
	}
	dst := make(map[string]interface{}, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
