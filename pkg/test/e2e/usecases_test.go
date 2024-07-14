package e2e

import (
	"flag"
	"fmt"
	"log"
	"testing"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/test/monolithic"
	rabbitmq_test "github.com/lamassuiot/lamassuiot/v2/pkg/test/subsystems/async-messaging/rabbitmq"
	keyvaultkv2_test "github.com/lamassuiot/lamassuiot/v2/pkg/test/subsystems/cryptoengines/keyvaultkv2"
	postgres_test "github.com/lamassuiot/lamassuiot/v2/pkg/test/subsystems/storage/postgres"
)

var awsIoTManagerUser = flag.String("awsiot-keyid", "", "AWS IoT Manager AccessKeyID")
var awsIoTManagerPass = flag.String("awsiot-keysecret", "", "AWS IoT Manager SecretAccessKey")
var awsIoTManagerRegion = flag.String("awsiot-region", "", "AWS IoT Manager Region")
var awsIoTManagerAccountID = flag.String("awsiot-id", "", "AWS IoT Core Account ConnectorID")
var awsIoTManagerEndpoint = flag.String("awsiot-endpoint", "", "AWS IoT Core Endpoint")

func TestUseCase1(t *testing.T) {
	t.Skip("Skip until we have a reliable way to test this")

	cleanup := []func() error{}

	//capture future panics
	defer func() {
		if err := recover(); err != nil {
			fmt.Println("panic triggered cleanup")
		}

		for _, f := range cleanup {
			f()
		}
	}()

	checkEmptyFlags := []string{
		*awsIoTManagerUser,
		*awsIoTManagerPass,
		*awsIoTManagerRegion,
		*awsIoTManagerAccountID,
		*awsIoTManagerEndpoint,
	}

	for _, f := range checkEmptyFlags {
		if f == "" {
			t.Errorf("Empty AWS flag provided")
		}
	}

	pCleanup, storageConfig, err := postgres_test.RunPostgresDocker([]string{"ca", "alerts", "dmsmanager", "devicemanager", "cloudproxy"})
	if err != nil {
		log.Fatalf("could not launch Postgres: %s", err)
	}
	cleanup = append(cleanup, pCleanup)

	fmt.Println("Crypto Engines")
	fmt.Println(">> launching docker: Hashicorp Vault ...")
	vCleanup, vaultConfig, _, err := keyvaultkv2_test.RunHashicorpVaultDocker()
	if err != nil {
		log.Fatalf("could not launch Hashicorp Vault: %s", err)
	}
	cleanup = append(cleanup, vCleanup)

	fmt.Println("Async Messaging Engine")
	fmt.Println(">> launching docker: RabbitMQ ...")
	rmqCleanup, rmqConfig, _, err := rabbitmq_test.RunRabbitMQDocker()
	if err != nil {
		log.Fatalf("could not launch RabbitMQ: %s", err)
	}

	cleanup = append(cleanup, rmqCleanup)

	eventBus := config.EventBusEngine{
		LogLevel: config.Info,
		Enabled:  true,
		Provider: config.Amqp,
		Amqp:     *rmqConfig,
	}

	conf := config.MonolithicConfig{
		GatewayPort:        0,
		Logs:               config.BaseConfigLogging{Level: config.None},
		SubscriberEventBus: eventBus,
		PublisherEventBus:  eventBus,
		Domain:             "dev.lamassu.test",
		AssemblyMode:       config.Http,
		CryptoEngines: config.CryptoEngines{
			LogLevel:      config.Info,
			DefaultEngine: "golang-1",
			GolangHashicorpVaultKV2Provider: []config.HashicorpVaultCryptoEngineConfig{
				{
					HashicorpVaultSDK: *vaultConfig,
					ID:                "dockertest-hcpvault-kvv2",
					Metadata:          make(map[string]interface{}),
				},
			},
			GolangFilesystemProvider: []config.GolangFilesystemEngineConfig{
				{
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
			Enabled:     true,
			ConnectorID: fmt.Sprintf("aws.%s", *awsIoTManagerAccountID),
			AWSSDKConfig: config.AWSSDKConfig{
				AccessKeyID:     *awsIoTManagerUser,
				SecretAccessKey: config.Password(*awsIoTManagerPass),
				Region:          *awsIoTManagerRegion,
			},
		},
	}

	port, err := monolithic.RunMonolithicLamassuPKI(conf)
	if err != nil {
		t.Errorf("error while running monolithic PKI: %s", err)
	}

	err = RunUseCase1(UseCase1Input{
		LamassuHostname:    "localhost",
		LamassuPort:        port,
		LamassuHTTProtocol: "https",
		DeviceIDPrefix:     "smartmeter",
		DMSPrefix:          "smart_metering_factory_x",
		AwsAccountID:       *awsIoTManagerAccountID,
		AwsIotCoreEndpoint: *awsIoTManagerEndpoint,
		AwsShadowName:      "lamassu-identity",
	})

	if err != nil {
		t.Errorf("error while running use case 1: %s", err)
	}
}
