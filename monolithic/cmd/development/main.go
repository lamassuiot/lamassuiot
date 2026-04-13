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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/eventbus/inmemory"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/sampledata"
	"github.com/lamassuiot/lamassuiot/monolithic/v3/pkg/storage/sqlite"
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
	standardDockerPorts := flag.Bool("standard-docker-ports", true, "use standard docker ports for services (RabbitMQ, Postgres, Vault, etc.)")

	hsmModule := flag.String("hsm-module-path", "", "enable HSM support")

	awsIoTManager := flag.Bool("awsiot", false, "enable AWS IoT Manager")
	awsIoTManagerAKID := flag.String("awsiot-keyid", "", "AWS IoT Manager AccessKeyID")
	awsIoTManagerSAK := flag.String("awsiot-keysecret", "", "AWS IoT Manager SecretAccessKey")
	awsIoTManagerST := flag.String("awsiot-sessiontoken", "", "AWS IoT Manager SessionToken")
	awsIoTManagerRegion := flag.String("awsiot-region", "eu-west-1", "AWS IoT Manager Region")
	awsIoTManagerID := flag.String("awsiot-id", "", "AWS IoT Manager ConnectorID")
	cryptoengineOptions := flag.String("cryptoengines", "filesystem", ", separated list of crypto engines to enable ['aws-secrets','aws-kms','vault','pkcs11','filesystem']")
	disableMonitor := flag.Bool("disable-monitor", false, "disable crypto monitoring")
	disableEventbus := flag.Bool("disable-eventbus", false, "disable eventbus")
	useAwsEventbus := flag.Bool("use-aws-eventbus", false, "use AWS Eventbus")
	useInMemoryEventbus := flag.Bool("inmemory-eventbus", false, "use in-memory eventbus (no Docker required)")
	disableUI := flag.Bool("disable-ui", false, "Disable UI docker loading")
	useSqlite := flag.Bool("sqlite", false, "use sqlite storage engine")
	sampleData := flag.Bool("sample-data", false, "populate the server with sample data for manual testing")
	flag.Parse()

	fmt.Println("===================== FLAGS ======================")

	fmt.Printf("AWS IoT Manager Enabled: %v\n", *awsIoTManager)
	fmt.Printf("Sample Data Enabled: %v\n", *sampleData)
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
			log.Fatalf("Could not list containers: %s", err)
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
	if *useSqlite {
		sqlite.Register()
	}
	if *useInMemoryEventbus {
		inmemory.Register()
	}

	fmt.Println("Storage Engine")
	var storageConfig cconfig.PluggableStorageEngine
	var err error

	if *useSqlite {
		fmt.Println(">> using SQLite ...")
		sqlite.Register()
		storageConfig = cconfig.PluggableStorageEngine{
			LogLevel: cconfig.Info,
			Provider: cconfig.SQLite,
			Config: map[string]interface{}{
				"path": "file::memory:?cache=shared",
			},
		}
	} else {
		fmt.Println(">> launching docker: Postgres ...")
		posgresSubsystem := subsystems.GetSubsystemBuilder[subsystems.StorageSubsystem](subsystems.Postgres)
		posgresSubsystem.Prepare([]string{"ca", "alerts", "dmsmanager", "devicemanager", "va", "kms"})
		backend, err := posgresSubsystem.Run(*standardDockerPorts)
		if err != nil {
			log.Fatalf("could not launch Postgres: %s", err)
		}

		storageConfig = backend.Config.(cconfig.PluggableStorageEngine)

		fmt.Printf(" 	-- postgres port: %d\n", storageConfig.Config["port"].(int))
		fmt.Printf(" 	-- postgres user: %s\n", storageConfig.Config["username"].(string))
		fmt.Printf(" 	-- postgres pass: %s\n", storageConfig.Config["password"].(cconfig.Password))
	}

	fmt.Println("Crypto Engines")

	var vaultCryptoEngine cconfig.CryptoEngineConfig
	rootToken := ""
	if _, ok := cryptoengineOptionsMap[Vault]; ok {
		fmt.Println(">> launching docker: Hashicorp Vault ...")
		vaultSubsystem, err := subsystems.GetSubsystemBuilder[subsystems.Subsystem](subsystems.Vault).Run(*standardDockerPorts)
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
		awsSubsystem, err := subsystems.GetSubsystemBuilder[subsystems.Subsystem](subsystems.Aws).Run(*standardDockerPorts)
		if err != nil {
			log.Fatalf("could not launch AWS Platform: %s", err)
		}

		awsBaseCryptoEngine = awsSubsystem.Config.(cconfig.CryptoEngineConfig)
	}

	hsmModulePath := *hsmModule
	var pkcs11Cfg cconfig.CryptoEngineConfig
	if _, ok := cryptoengineOptionsMap[Pkcs11]; ok && hsmModulePath != "" {
		fmt.Println(">> launching docker: SoftHSM ...")
		pkcs11SubsystemBuilder := subsystems.GetSubsystemBuilder[subsystems.ParametrizedSubsystem](subsystems.Pkcs11)
		pkcs11SubsystemBuilder.Prepare(map[string]interface{}{"hsmModulePath": hsmModulePath})
		pkcs11Subsystem, err := pkcs11SubsystemBuilder.Run(*standardDockerPorts)
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

	if !*disableEventbus && *useInMemoryEventbus {
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
	} else if !*disableEventbus && !*useAwsEventbus {
		fmt.Println(">> launching docker: RabbitMQ ...")
		rabbitmqSubsystem, err := subsystems.GetSubsystemBuilder[subsystems.Subsystem](subsystems.RabbitMQ).Run(*standardDockerPorts)
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
	} else if !*disableEventbus && *useAwsEventbus {
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
	fmt.Printf(">> UI Enabled : %v\n", !*disableUI)

	cloudConnectors := "[]"
	if *awsIoTManagerID != "" {
		cloudConnectors = fmt.Sprintf("[\"aws.%s\"]", *awsIoTManagerID)
	}

	additionalPortsRouting := map[string]int{}

	if !*disableUI {
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

		pwd, err := os.Getwd()
		if err != nil {
			log.Fatalf("could not get current directory: %s", err)
		}

		mounts := []docker.HostMount{}
		createAndMountOpaFile := func(fname, content string) error {
			os.Mkdir(fmt.Sprintf("%s/opa-testdata", pwd), 0755) // #nosec
			initScriptFname := fmt.Sprintf("%s/opa-testdata/%s", pwd, fname)
			err = os.WriteFile(initScriptFname, []byte(content), 0644) // #nosec
			if err != nil {
				return err
			}

			mounts = append(mounts, docker.HostMount{
				Type:   "bind",
				Target: "/policies/" + fname,
				Source: initScriptFname,
			})
			return nil
		}

		err = createAndMountOpaFile("pqc.rego", OPA_PQC_POLICY)
		if err != nil {
			log.Fatalf("could not create OPA policy file: %s", err)
		}

		err = createAndMountOpaFile("eccg_v2.rego", OPA_ECCG_V2_POLICY)
		if err != nil {
			log.Fatalf("could not create OPA policy file: %s", err)
		}

		_, opaAPIContainer, _, err := dockerrunner.RunDocker(dockertest.RunOptions{
			Repository: "openpolicyagent/opa", // image
			Tag:        "latest",              // version
			ExtraHosts: []string{"host.docker.internal:host-gateway"},
			Labels: map[string]string{
				"group": "lamassuiot-monolithic",
			},
			Cmd: []string{
				"run",
				"--addr=0.0.0.0:8181",
				"--server",
				"/policies",
			},
		}, func(hc *docker.HostConfig) {
			hc.AutoRemove = false
			hc.Mounts = mounts
			hc.PortBindings = map[docker.Port][]docker.PortBinding{
				"8181/tcp": {
					{
						HostIP:   "0.0.0.0",
						HostPort: "8181",
					},
				},
			}
		})

		opaAPIPort, _ := strconv.Atoi(opaAPIContainer.GetPort("8181/tcp"))

		_, cbomKitAPIContainer, _, err := dockerrunner.RunDocker(dockertest.RunOptions{
			Repository: "ghcr.io/cbomkit/cbomkit", // image
			Tag:        "edge",                    // version
			Env: []string{
				"CBOMKIT_DB_TYPE=postgresql",
				"CBOMKIT_DB_JDBC_URL=jdbc:postgresql://host.docker.internal:5432/cbom",
				"CBOMKIT_PORT=8081",
				"CBOMKIT_DB_USERNAME=" + storageConfig.Config["username"].(string),
				"CBOMKIT_DB_PASSWORD=" + string(storageConfig.Config["password"].(cconfig.Password)),
				"CBOMKIT_FRONTEND_URL_CORS=http://localhost:8000,http://localhost:9002",
				"CBOMKIT_OPA_API_BASE=http://host.docker.internal:8181", // http://opa:8181
			},
			ExtraHosts: []string{"host.docker.internal:host-gateway"},
			Labels: map[string]string{
				"group": "lamassuiot-monolithic",
			},
		}, func(hc *docker.HostConfig) {
			hc.AutoRemove = false
			hc.PortBindings = map[docker.Port][]docker.PortBinding{
				"8081/tcp": {
					{
						HostIP:   "0.0.0.0",
						HostPort: "8081",
					},
				},
			}
		})

		cbomAPIPort, _ := strconv.Atoi(cbomKitAPIContainer.GetPort("8081/tcp"))

		_, container, _, err = dockerrunner.RunDocker(dockertest.RunOptions{
			Repository: "ghcr.io/cbomkit/cbomkit-frontend", // image
			Tag:        "edge",                             // version
			Env: []string{
				"VUE_APP_HTTP_API_BASE=http://localhost:8081",
				"VUE_APP_WS_API_BASE=ws://localhost:8081",
				"VUE_APP_TITLE=CBOMkit-LAMASSU",
				"VUE_APP_VIEWER_ONLY=false",
			},
			Labels: map[string]string{
				"group": "lamassuiot-monolithic",
			},
		}, func(hc *docker.HostConfig) {
			hc.AutoRemove = true
			hc.PortBindings = map[docker.Port][]docker.PortBinding{
				"8000/tcp": {
					{
						HostIP:   "0.0.0.0",
						HostPort: "8000",
					},
				},
			}

		})

		cbomFrontPort, _ := strconv.Atoi(container.GetPort("8000/tcp"))
		fmt.Println(cbomFrontPort)

		additionalPortsRouting["/opa"] = opaAPIPort
		additionalPortsRouting["/cbomkit-api"] = cbomAPIPort
		additionalPortsRouting["/cbomkit"] = cbomFrontPort

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
			Enabled:   !*disableMonitor,
			Frequency: "2m",
		},
		Storage:            *pluglableStorageConfig,
		PopulateSampleData: *sampleData,
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
		AdditionalPortsRouting: additionalPortsRouting,
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
	if *sampleData {
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

const OPA_PQC_POLICY = `
package policies

##################
# Helper functions
##################

is_algorithm(component) if {
	# component.type == "cryptographic-asset"
	component.cryptoProperties.assetType == "algorithm"
}

is_asymmetric(component) if {
	is_algorithm(component)
	asymmetric_primitives := ["signature", "keyagree", "kem", "pke", "unknown", "other"]
	component.cryptoProperties.algorithmProperties.primitive in asymmetric_primitives
}

in_whitelist(primitive, id, whitelist) := "quantum-safe" if {
	id in whitelist
} else := "unknown" if {
	primitive in ["unknown", "other"]
} else := "quantum-vulnerable"

at_least(value, ref) := "quantum-safe" if {
	value >= ref
} else := "quantum-vulnerable"

##################
# Rules
##################

# Mark async algorithms as "quantum-safe" or "quantum-vulnerable"
# if name is in whitelist or not
pqc.findings contains finding if {
	some component in input.components
	is_asymmetric(component)
	not component.cryptoProperties.oid

	# whitelist
	qs_algorithms := [
		"ml-kem", "ml-dsa", "slh-dsa", "pqxdh",
		"bike", "mceliece", "frodokem", "hqc",
		"kyber", "ntru", "crystals", "falcon",
		"mayo", "sphincs", "xmss", "lms",
	]

	finding := {
		"rule": "asymmetric_quantum_safe",
		"result": in_whitelist(
			component.cryptoProperties.algorithmProperties.primitive,
			component.name,
			qs_algorithms,
		),
		"value": component.name,
		"referenceList": qs_algorithms,
		"bom-ref": component["bom-ref"],
		"property": "name",
	}
}

# Mark async algorithms as "quantum-safe" or "quantum-vulnerable"
# if oid is in whitelist or not
pqc.findings contains finding if {
	some component in input.components
	is_asymmetric(component)

	# whitelist
	qs_oids := [
		"1.3.6.1.4.1.2.267.12.4.4", "1.3.6.1.4.1.2.267.12.6.5", "1.3.6.1.4.1.2.267.12.8.7",
		"1.3.9999.6.4.16", "1.3.9999.6.7.16", "1.3.9999.6.4.13", "1.3.9999.6.7.13",
		"1.3.9999.6.5.12", "1.3.9999.6.8.12", "1.3.9999.6.5.10", "1.3.9999.6.8.10",
		"1.3.9999.6.6.12", "1.3.9999.6.9.12", "1.3.9999.6.6.10", "1.3.9999.6.9.10",
		"1.3.6.1.4.1.22554.5.6.1", "1.3.6.1.4.1.22554.5.6.2", "1.3.6.1.4.1.22554.5.6.3",
	]

	finding := {
		"rule": "asymmetric_quantum_safe",
		"result": in_whitelist(
			component.cryptoProperties.algorithmProperties.primitive,
			component.cryptoProperties.oid,
			qs_oids,
		),
		"value": component.cryptoProperties.oid,
		"referenceList": qs_oids,
		"bom-ref": component["bom-ref"],
		"property": "cryptoProperties.oid",
	}
}

# Mark algorithms with nistQuantumSecurityLevel >= min
# "quantum-safe", otherwise "quantum-vulnerable"
pqc.findings contains finding if {
	some component in input.components
	is_algorithm(component)

	# exists
	component.cryptoProperties.algorithmProperties.nistQuantumSecurityLevel

	# minimum nist qs level
	qs_min_nist_level := 1

	finding := {
		"rule": "nist_qs_level",
		"result": at_least(
			component.cryptoProperties.algorithmProperties.nistQuantumSecurityLevel,
			qs_min_nist_level,
		),
		"value": component.cryptoProperties.algorithmProperties.nistQuantumSecurityLevel,
		"referenceValue": qs_min_nist_level,
		"bom-ref": component["bom-ref"],
		"property": "nistQuantumSecurityLevel",
	}
}

# Mark symmetric algorithms as "na"
pqc.findings contains finding if {
	some component in input.components
	not is_asymmetric(component)

	finding := {
		"rule": "symmetric_na",
		"result": "NA",
		"value": component.cryptoProperties.algorithmProperties.primitive,
		"bom-ref": component["bom-ref"],
		"property": "algorithmProperties.primitive",
	}
}
`

const OPA_ECCG_V2_POLICY = `
package policies

############################
# Helpers
############################

trim(x) := y if {
	y := trim_space(sprintf("%v", [x]))
}

normalize(x) := y if {
	x != null
	y := lower(trim(x))
}

name(component) := normalize(object.get(component, "name", ""))

bom_ref(component) := object.get(component, "bom-ref", "")

crypto(component) := object.get(component, "cryptoProperties", {})

alg_props(component) := object.get(crypto(component), "algorithmProperties", {})

proto_props(component) := object.get(crypto(component), "protocolProperties", {})

asset_type(component) := normalize(object.get(crypto(component), "assetType", ""))

primitive(component) := normalize(object.get(alg_props(component), "primitive", ""))

oid(component) := normalize(object.get(crypto(component), "oid", ""))

num(x, dflt) := n if {
	n := to_number(x)
} else := dflt

key_bits(component) := n if {
	n := num(object.get(alg_props(component), "keyLength", null), -1)
	n >= 0
} else := n if {
	n := num(object.get(alg_props(component), "keySize", null), -1)
	n >= 0
} else := n if {
	n := num(object.get(alg_props(component), "length", null), -1)
	n >= 0
} else := -1

hash_bits(component) := n if {
	n := num(object.get(alg_props(component), "outputSize", null), -1)
	n >= 0
} else := n if {
	n := num(object.get(alg_props(component), "hashLength", null), -1)
	n >= 0
} else := -1

modulus_bits(component) := n if {
	n := num(object.get(alg_props(component), "modulusLength", null), -1)
	n >= 0
} else := n if {
	n := num(object.get(alg_props(component), "modulusSize", null), -1)
	n >= 0
} else := -1

subgroup_bits(component) := n if {
	n := num(object.get(alg_props(component), "subgroupSize", null), -1)
	n >= 0
} else := n if {
	n := num(object.get(alg_props(component), "qLength", null), -1)
	n >= 0
} else := -1

public_exponent_bits(component) := n if {
	n := num(object.get(alg_props(component), "publicExponentLength", null), -1)
	n >= 0
} else := -1

curve_name(component) := normalize(
	object.get(
		alg_props(component),
		"curve",
		object.get(crypto(component), "curve", "")
	)
)

tls_version(component) := normalize(
	object.get(
		proto_props(component),
		"version",
		object.get(crypto(component), "protocolVersion", "")
	)
)

tls_cipher_suite(component) := normalize(
	object.get(
		proto_props(component),
		"cipherSuite",
		object.get(crypto(component), "cipherSuite", "")
	)
)

status_to_result(status) := "quantum-safe" if {
	status == "recommended"
} else := "quantum-safe" if {
	status == "legacy"
} else := "quantum-vulnerable" if {
	status == "not-agreed"
} else := "NA" if {
	status == "na"
} else := "unknown"

mk_finding(component, rule, status, property, value) := {
	"bom-ref": bom_ref(component),
	"rule": rule,
	"result": status_to_result(status),
	"eccg_status": status,
	"property": property,
	"value": value,
}

############################
# Classification helpers
############################

is_crypto_asset(component) if {
	asset_type(component) == "cryptographic-asset"
}

is_algorithm(component) if {
	is_crypto_asset(component)
}

is_tls(component) if {
	tls_version(component) != ""
}

is_tls(component) if {
	contains(name(component), "tls")
}

is_aes_name(n) if {
	n == "aes"
}

is_aes_name(n) if {
	contains(n, "aes-")
}

is_3des_name(n) if {
	n == "triple-des"
}

is_3des_name(n) if {
	n == "3des"
}

is_3des_name(n) if {
	contains(n, "des-ede3")
}

is_rsa_name(n) if {
	n == "rsa"
}

is_rsa_name(n) if {
	contains(n, "rsa")
}

is_rsa_oaep_name(n) if {
	n == "rsa-oaep"
}

is_rsa_oaep_name(n) if {
	contains(n, "oaep")
}

is_rsa_pkcs1_v15_name(n) if {
	n == "rsa-pkcs1v1.5"
}

is_rsa_pkcs1_v15_name(n) if {
	contains(n, "pkcs#1v1.5")
}

is_shamir_name(n) if {
	n == "shamir"
}

is_shamir_name(n) if {
	contains(n, "shamir")
}

is_ffdlog_name(n) if {
	contains(n, "ffdhe")
}

is_ffdlog_name(n) if {
	contains(n, "modp")
}

is_ffdlog_name(n) if {
	contains(n, "dh")
}

is_ffdlog_name(n) if {
	contains(n, "dsa")
}

is_ffdlog_name(n) if {
	contains(n, "schnorr")
}

is_ffdlog_primitive(p) if {
	p == "keyagree"
}

is_ffdlog_primitive(p) if {
	p == "signature"
}

is_ffdlog_primitive(p) if {
	p == "pke"
}

is_sha2_sha3_recommended(n, h) if {
	n == "sha-256"
	h == 256
}

is_sha2_sha3_recommended(n, h) if {
	n == "sha-384"
	h == 384
}

is_sha2_sha3_recommended(n, h) if {
	n == "sha-512"
	h == 512
}

is_sha2_sha3_recommended(n, h) if {
	n == "sha-512/256"
	h == 256
}

is_sha2_sha3_recommended(n, h) if {
	n == "sha3-256"
	h == 256
}

is_sha2_sha3_recommended(n, h) if {
	n == "sha3-384"
	h == 384
}

is_sha2_sha3_recommended(n, h) if {
	n == "sha3-512"
	h == 512
}

is_sha_legacy(n, h) if {
	n == "sha-224"
	h == 224
}

is_sha_legacy(n, h) if {
	n == "sha-512/224"
	h == 224
}

############################
# ECCG v2 algorithm status
############################

eccg_algorithm_status(component) := {
	"status": "recommended",
	"property": "keyLength",
	"value": key_bits(component),
	"ref": "AES k in {128,192,256}",
} if {
	n := name(component)
	is_aes_name(n)
	key_bits(component) in {128, 192, 256}
}

eccg_algorithm_status(component) := {
	"status": "legacy",
	"property": "keyLength",
	"value": key_bits(component),
	"ref": "3DES k=168",
} if {
	n := name(component)
	is_3des_name(n)
	key_bits(component) == 168
}

eccg_algorithm_status(component) := {
	"status": "recommended",
	"property": "hashLength",
	"value": hash_bits(component),
	"ref": "SHA-2/SHA-3 agreed",
} if {
	n := name(component)
	h := hash_bits(component)
	is_sha2_sha3_recommended(n, h)
}

eccg_algorithm_status(component) := {
	"status": "legacy",
	"property": "hashLength",
	"value": hash_bits(component),
	"ref": "SHA-224 / SHA-512/224 legacy [2025]",
} if {
	n := name(component)
	h := hash_bits(component)
	is_sha_legacy(n, h)
}

eccg_algorithm_status(component) := {
	"status": "recommended",
	"property": "name",
	"value": name(component),
	"ref": "Shamir secret sharing",
} if {
	n := name(component)
	is_shamir_name(n)
}

eccg_algorithm_status(component) := {
	"status": "recommended",
	"property": "name",
	"value": name(component),
	"ref": "CMAC / CBC-MAC / GMAC",
} if {
	name(component) in {"cmac", "cbc-mac", "gmac"}
}

eccg_algorithm_status(component) := {
	"status": "recommended",
	"property": "keyLength",
	"value": key_bits(component),
	"ref": "HMAC k>=125",
} if {
	name(component) == "hmac"
	key_bits(component) >= 125
}

eccg_algorithm_status(component) := {
	"status": "legacy",
	"property": "keyLength",
	"value": key_bits(component),
	"ref": "HMAC 100<=k<125",
} if {
	name(component) == "hmac"
	key_bits(component) >= 100
	key_bits(component) < 125
}

eccg_algorithm_status(component) := {
	"status": "legacy",
	"property": "keyLength",
	"value": key_bits(component),
	"ref": "HMAC-SHA-1 k>=100 legacy [2030]",
} if {
	n := name(component)
	n in {"hmac-sha-1", "hmac-sha1"}
	key_bits(component) >= 100
}

eccg_algorithm_status(component) := {
	"status": "recommended",
	"property": "keyLength",
	"value": key_bits(component),
	"ref": "KMAC128 k>=125",
} if {
	name(component) == "kmac128"
	key_bits(component) >= 125
}

eccg_algorithm_status(component) := {
	"status": "recommended",
	"property": "keyLength",
	"value": key_bits(component),
	"ref": "KMAC256 k>=250",
} if {
	name(component) == "kmac256"
	key_bits(component) >= 250
}

eccg_algorithm_status(component) := {
	"status": "recommended",
	"property": "name",
	"value": name(component),
	"ref": "Agreed symmetric constructions",
} if {
	name(component) in {
		"encrypt-then-mac",
		"ccm",
		"gcm",
		"eax",
		"siv",
		"aes-keywrap",
		"aes-kw",
		"aes-kwp",
		"ansi-x9.63-kdf",
		"hkdf",
		"pbkdf2",
		"catkdf",
		"caskdf",
		"xts",
	}
}

eccg_algorithm_status(component) := {
	"status": "legacy",
	"property": "name",
	"value": name(component),
	"ref": "MAC-then-Encrypt / Encrypt-and-MAC legacy [2025]",
} if {
	name(component) in {"mac-then-encrypt", "encrypt-and-mac", "cbc-essiv"}
}

eccg_algorithm_status(component) := {
	"status": "recommended",
	"property": "modulusLength",
	"value": modulus_bits(component),
	"ref": "RSA n>=3000 and log2(e)>16",
} if {
	n := name(component)
	is_rsa_name(n)
	modulus_bits(component) >= 3000
	public_exponent_bits(component) > 16
}

eccg_algorithm_status(component) := {
	"status": "legacy",
	"property": "modulusLength",
	"value": modulus_bits(component),
	"ref": "RSA 1900<=n<3000 and log2(e)>16 legacy [2025]",
} if {
	n := name(component)
	is_rsa_name(n)
	modulus_bits(component) >= 1900
	modulus_bits(component) < 3000
	public_exponent_bits(component) > 16
}

eccg_algorithm_status(component) := {
	"status": "recommended",
	"property": "modulusLength",
	"value": {"p": modulus_bits(component), "q": subgroup_bits(component)},
	"ref": "FF-DLOG p>=3000 q>=250",
} if {
	p := primitive(component)
	is_ffdlog_primitive(p)
	n := name(component)
	is_ffdlog_name(n)
	modulus_bits(component) >= 3000
	subgroup_bits(component) >= 250
}

eccg_algorithm_status(component) := {
	"status": "legacy",
	"property": "modulusLength",
	"value": {"p": modulus_bits(component), "q": subgroup_bits(component)},
	"ref": "FF-DLOG p>=1900 q>=200 legacy [2025]",
} if {
	p := primitive(component)
	is_ffdlog_primitive(p)
	n := name(component)
	is_ffdlog_name(n)
	modulus_bits(component) >= 1900
	modulus_bits(component) < 3000
	subgroup_bits(component) >= 200
}

eccg_algorithm_status(component) := {
	"status": "recommended",
	"property": "name",
	"value": name(component),
	"ref": "MODP/FFDHE 3072+",
} if {
	n := name(component)
	n in {
		"3072-bit modp group",
		"4096-bit modp group",
		"6144-bit modp group",
		"8192-bit modp group",
		"3072-bit ffdhe group",
		"4096-bit ffdhe group",
		"6144-bit ffdhe group",
		"8192-bit ffdhe group",
	}
}

eccg_algorithm_status(component) := {
	"status": "legacy",
	"property": "name",
	"value": name(component),
	"ref": "2048-bit MODP/FFDHE legacy [2025]",
} if {
	n := name(component)
	n in {"2048-bit modp group", "2048-bit ffdhe group"}
}

eccg_algorithm_status(component) := {
	"status": "recommended",
	"property": "curve",
	"value": curve_name(component),
	"ref": "Agreed ECC curves",
} if {
	curve_name(component) in {
		"brainpoolp256r1",
		"brainpoolp384r1",
		"brainpoolp512r1",
		"nist p-256",
		"nist p-384",
		"nist p-521",
		"p-256",
		"p-384",
		"p-521",
		"frp256v1",
	}
}

eccg_algorithm_status(component) := {
	"status": "recommended",
	"property": "name",
	"value": name(component),
	"ref": "RSA-OAEP",
} if {
	n := name(component)
	is_rsa_oaep_name(n)
}

eccg_algorithm_status(component) := {
	"status": "legacy",
	"property": "name",
	"value": name(component),
	"ref": "RSA PKCS#1 v1.5",
} if {
	n := name(component)
	is_rsa_pkcs1_v15_name(n)
}

eccg_algorithm_status(component) := {
	"status": "recommended",
	"property": "name",
	"value": name(component),
	"ref": "Agreed signature schemes",
} if {
	name(component) in {
		"rsa-pss",
		"kcdsa",
		"schnorr",
		"dsa",
		"ec-kcdsa",
		"ecdsa",
		"ec-dsa",
		"ec-gdsa",
		"ec-schnorr",
		"ml-dsa",
		"xmss",
		"lms",
		"slh-dsa",
	}
}

eccg_algorithm_status(component) := {
	"status": "legacy",
	"property": "name",
	"value": name(component),
	"ref": "RSA PKCS#1 v1.5 signature legacy",
} if {
	n := name(component)
	is_rsa_pkcs1_v15_name(n)
}

eccg_algorithm_status(component) := {
	"status": "recommended",
	"property": "name",
	"value": name(component),
	"ref": "Agreed KE/KEM schemes",
} if {
	name(component) in {
		"dh",
		"dlies-kem",
		"ec-dh",
		"ecdh",
		"ecies-kem",
		"ml-kem",
		"frodokem",
	}
}

eccg_algorithm_status(component) := {
	"status": "recommended",
	"property": "name",
	"value": name(component),
	"ref": "Agreed DRBG",
} if {
	name(component) in {"hmac_drbg", "hash_drbg", "ctr_drbg"}
}

############################
# TLS status
############################

eccg_tls_version_status(component) := {
	"status": "recommended",
	"property": "protocolVersion",
	"value": tls_version(component),
	"ref": "TLSv1.3",
} if {
	is_tls(component)
	tls_version(component) == "tlsv1.3"
}

eccg_tls_version_status(component) := {
	"status": "legacy",
	"property": "protocolVersion",
	"value": tls_version(component),
	"ref": "TLSv1.2",
} if {
	is_tls(component)
	tls_version(component) == "tlsv1.2"
}

eccg_tls_cipher_status(component) := {
	"status": "recommended",
	"property": "cipherSuite",
	"value": tls_cipher_suite(component),
	"ref": "ECCG TLS v1.3 agreed suites",
} if {
	is_tls(component)
	tls_cipher_suite(component) in {
		"tls_aes_256_gcm_sha384",
		"tls_aes_128_gcm_sha256",
		"tls_aes_128_ccm_sha256",
	}
}

eccg_tls_cipher_status(component) := {
	"status": "legacy",
	"property": "cipherSuite",
	"value": tls_cipher_suite(component),
	"ref": "ECCG TLS v1.2 agreed legacy suites",
} if {
	is_tls(component)
	tls_cipher_suite(component) in {
		"tls_ecdhe_ecdsa_with_aes_256_gcm_sha384",
		"tls_ecdhe_ecdsa_with_aes_128_gcm_sha256",
		"tls_ecdhe_ecdsa_with_aes_256_ccm",
		"tls_ecdhe_ecdsa_with_aes_128_ccm",
		"tls_ecdhe_ecdsa_with_aes_256_cbc_sha384",
		"tls_ecdhe_ecdsa_with_aes_128_cbc_sha256",
		"tls_ecdhe_rsa_with_aes_256_cbc_sha384",
		"tls_ecdhe_rsa_with_aes_128_cbc_sha256",
		"tls_ecdhe_rsa_with_aes_256_gcm_sha384",
		"tls_ecdhe_rsa_with_aes_128_gcm_sha256",
		"tls_dhe_rsa_with_aes_256_gcm_sha384",
		"tls_dhe_rsa_with_aes_128_gcm_sha256",
		"tls_dhe_rsa_with_aes_256_ccm",
		"tls_dhe_rsa_with_aes_128_ccm",
		"tls_dhe_rsa_with_aes_256_cbc_sha256",
		"tls_dhe_rsa_with_aes_128_cbc_sha256",
		"tls_rsa_with_aes_256_gcm_sha384",
		"tls_rsa_with_aes_128_gcm_sha256",
		"tls_rsa_with_aes_256_ccm",
		"tls_rsa_with_aes_128_ccm",
		"tls_rsa_with_aes_256_cbc_sha256",
		"tls_rsa_with_aes_128_cbc_sha256",
	}
}

############################
# Findings
############################

eccg_v2.findings contains finding if {
	some component in input.components
	s := eccg_algorithm_status(component)
	finding := mk_finding(
		component,
		"eccg_v2_algorithm_status",
		s.status,
		s.property,
		s.value,
	)
}

eccg_v2.findings contains finding if {
	some component in input.components
	s := eccg_tls_version_status(component)
	finding := mk_finding(
		component,
		"eccg_v2_tls_version_status",
		s.status,
		s.property,
		s.value,
	)
}

eccg_v2.findings contains finding if {
	some component in input.components
	s := eccg_tls_cipher_status(component)
	finding := mk_finding(
		component,
		"eccg_v2_tls_cipher_suite_status",
		s.status,
		s.property,
		s.value,
	)
}
`
