package assemblers

import (
	"crypto/elliptic"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"slices"

	"github.com/lamassuiot/lamassuiot/v2/pkg/clients"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage/postgres"
	rabbitmq_test "github.com/lamassuiot/lamassuiot/v2/pkg/test/subsystems/async-messaging/rabbitmq"
	vault_test "github.com/lamassuiot/lamassuiot/v2/pkg/test/subsystems/cryptoengines/keyvaultkv2"
	postgres_test "github.com/lamassuiot/lamassuiot/v2/pkg/test/subsystems/storage/postgres"
)

type CryptoEngine int

const (
	_ CryptoEngine = iota
	GOLANG
	VAULT
	AWS_SECRETS
	AWS_KMS
)

type Service int

const (
	_ Service = iota
	CA
	DEVICE_MANAGER
	VA
	DMS_MANAGER
)

type TestEventBusConfig struct {
	config     config.EventBusEngine
	BeforeEach func() error
	AfterSuite func()
}

type TestStorageEngineConfig struct {
	config     config.PluggableStorageEngine
	BeforeEach func() error
	AfterSuite func()
}

type TestCryptoEngineConfig struct {
	config     config.CryptoEngines
	BeforeEach func() error
	AfterSuite func()
}

type CATestServer struct {
	Service    services.CAService
	HttpCASDK  services.CAService
	BeforeEach func() error
	AfterSuite func()
}

type DMSManagerTestServer struct {
	Port                 int
	Service              services.DMSManagerService
	HttpDeviceManagerSDK services.DMSManagerService
	BeforeEach           func() error
	AfterSuite           func()
}

type DeviceManagerTestServer struct {
	Service              services.DeviceManagerService
	HttpDeviceManagerSDK services.DeviceManagerService
	BeforeEach           func() error
	AfterSuite           func()
}

type VATestServer struct {
	HttpServerURL string
	CaSDK         services.CAService
	BeforeEach    func() error
	AfterSuite    func()
}

type TestServer struct {
	CA            *CATestServer
	VA            *VATestServer
	DeviceManager *DeviceManagerTestServer
	DMSManager    *DMSManagerTestServer

	EventBus *TestEventBusConfig

	BeforeEach func() error
	AfterSuite func()
}

func PrepareRabbitMQForTest() (*TestEventBusConfig, error) {
	cleanup, conf, _, err := rabbitmq_test.RunRabbitMQDocker()
	if err != nil {
		return nil, err
	}

	return &TestEventBusConfig{
		config: config.EventBusEngine{
			LogLevel: config.Trace,
			Enabled:  true,
			Provider: config.Amqp,
			Amqp:     *conf,
		},
		AfterSuite: func() { cleanup() },
		BeforeEach: func() error {
			return nil
		},
	}, nil
}

func PreparePostgresForTest(dbs []string) (*TestStorageEngineConfig, error) {
	pConfig, postgresEngine := postgres_test.BeforeSuite(dbs)

	return &TestStorageEngineConfig{
		config: config.PluggableStorageEngine{LogLevel: config.Info, Provider: config.Postgres, Postgres: pConfig},
		BeforeEach: func() error {
			for _, dbName := range dbs {
				postgresEngine.BeforeEach()
				switch dbName {
				case "ca":
					_, err := postgres.NewCAPostgresRepository(postgresEngine.DB[dbName])
					if err != nil {
						return fmt.Errorf("could not run reinitialize CA tables: %s", err)
					}
				case "certificates":
					_, err := postgres.NewCertificateRepository(postgresEngine.DB[dbName])
					if err != nil {
						return fmt.Errorf("could not run reinitialize Certificates tables: %s", err)
					}
				case "devicemanager":
					_, err := postgres.NewDeviceManagerRepository(postgresEngine.DB[dbName])
					if err != nil {
						return fmt.Errorf("could not run reinitialize DeviceManager tables: %s", err)
					}
				case "dmsmanager":
					_, err := postgres.NewDMSManagerRepository(postgresEngine.DB[dbName])
					if err != nil {
						return fmt.Errorf("could not run reinitialize DMSManager tables: %s", err)
					}
				default:
					return fmt.Errorf("unknown db name: %s", dbName)
				}
			}
			return nil
		},
		AfterSuite: postgresEngine.AfterSuite,
	}, nil
}

func PrepareCryptoEnginesForTest(engines []CryptoEngine) *TestCryptoEngineConfig {
	beforeEachActions := []func() error{}
	afterSuiteActions := []func(){}

	cryptoEngineConf := config.CryptoEngines{
		LogLevel:      config.Info,
		DefaultEngine: "filesystem-1",
		GolangProvider: []config.GolangEngineConfig{
			{
				ID:               "filesystem-1",
				Metadata:         map[string]interface{}{},
				StorageDirectory: "/tmp/lms-test/",
			},
		},
	}

	beforeEachActions = append(beforeEachActions, func() error {
		return nil
	})
	afterSuiteActions = append(afterSuiteActions, func() {
		// noop
	})

	if slices.Contains(engines, VAULT) {
		vaultSDKConf, vaultSuite := vault_test.BeforeSuite()
		cryptoEngineConf.HashicorpVaultKV2Provider = []config.HashicorpVaultCryptoEngineConfig{
			{
				ID:                "vault-1",
				HashicorpVaultSDK: vaultSDKConf,
				Metadata:          map[string]interface{}{},
			},
		}
		beforeEachActions = append(beforeEachActions, vaultSuite.BeforeEach)
		afterSuiteActions = append(afterSuiteActions, vaultSuite.AfterSuite)
	}

	beforeEach := func() error {
		for _, action := range beforeEachActions {
			err := action()
			if err != nil {
				return err
			}
		}
		return nil
	}

	afterSuite := func() {
		for _, action := range afterSuiteActions {
			action()
		}
	}

	return &TestCryptoEngineConfig{
		config:     cryptoEngineConf,
		BeforeEach: beforeEach,
		AfterSuite: afterSuite,
	}
}

func BuildCATestServer(storageEngine *TestStorageEngineConfig, cryptoEngines *TestCryptoEngineConfig, eventBus *TestEventBusConfig) (*CATestServer, error) {
	storageEngine.config.LogLevel = config.Trace

	svc, scheduler, port, err := AssembleCAServiceWithHTTPServer(config.CAConfig{
		Logs: config.BaseConfigLogging{
			Level: config.Info,
		},
		Server: config.HttpServer{
			LogLevel:           config.Info,
			HealthCheckLogging: false,
			Protocol:           config.HTTP,
		},
		PublisherEventBus: eventBus.config,
		Storage:           storageEngine.config,
		CryptoEngines:     cryptoEngines.config,
		CryptoMonitoring: config.CryptoMonitoring{
			Enabled:   true,
			Frequency: "* * * * * *", //this CRON-like expression will scan certificate each second.
		},
		VAServerDomain: "dev.lamassu.test",
	}, models.APIServiceInfo{
		Version:   "test",
		BuildSHA:  "-",
		BuildTime: "-",
	})

	if err != nil {
		return nil, fmt.Errorf("could not assemble CA with HTTP server")
	}

	return &CATestServer{
		Service:   *svc,
		HttpCASDK: clients.NewHttpCAClient(http.DefaultClient, fmt.Sprintf("http://127.0.0.1:%d", port)),
		BeforeEach: func() error {
			return nil
		},
		AfterSuite: func() {
			scheduler.Stop()
		},
	}, nil
}

func BuildDeviceManagerServiceTestServer(storageEngine *TestStorageEngineConfig, eventBus *TestEventBusConfig, caTestServer *CATestServer) (*DeviceManagerTestServer, error) {
	svc, port, err := AssembleDeviceManagerServiceWithHTTPServer(config.DeviceManagerConfig{
		Logs: config.BaseConfigLogging{
			Level: config.Info,
		},
		Server: config.HttpServer{
			LogLevel:           config.Info,
			HealthCheckLogging: false,
			Protocol:           config.HTTP,
		},
		PublisherEventBus:  eventBus.config,
		SubscriberEventBus: eventBus.config,
		Storage:            storageEngine.config,
	}, caTestServer.Service, models.APIServiceInfo{
		Version:   "test",
		BuildSHA:  "-",
		BuildTime: "-",
	})
	if err != nil {
		return nil, fmt.Errorf("could not assemble Device Manager Service. Exiting: %s", err)
	}

	return &DeviceManagerTestServer{
		Service:              *svc,
		HttpDeviceManagerSDK: clients.NewHttpDeviceManagerClient(http.DefaultClient, fmt.Sprintf("http://127.0.0.1:%d", port)),
		BeforeEach: func() error {
			return nil
		},
		AfterSuite: func() {
			fmt.Println("TEST CLEANUP DEVICE MANAGER")
		},
	}, nil
}

func BuildDMSManagerServiceTestServer(storageEngine *TestStorageEngineConfig, eventBus *TestEventBusConfig, caTestServer *CATestServer, deviceManagerTestServer *DeviceManagerTestServer) (*DMSManagerTestServer, error) {
	key, _ := helpers.GenerateECDSAKey(elliptic.P256())
	crt, _ := helpers.GenerateSelfSignedCertificate(key, "downstream")
	downstreamPath := fmt.Sprintf("/tmp/%s", crt.SerialNumber.String())
	downstreamCertPath := fmt.Sprintf("%s.crt", downstreamPath)
	downstreamKeyPath := fmt.Sprintf("%s.key", downstreamPath)

	crtPem := helpers.CertificateToPEM(crt)
	err := os.WriteFile(downstreamCertPath, []byte(crtPem), 0600)
	if err != nil {
		return nil, fmt.Errorf("could not save downstream cert. Exiting: %s", err)
	}

	keyPem, _ := helpers.PrivateKeyToPEM(key)
	err = os.WriteFile(downstreamKeyPath, []byte(keyPem), 0600)
	if err != nil {
		return nil, fmt.Errorf("could not save downstream cert. Exiting: %s", err)
	}

	svc, port, err := AssembleDMSManagerServiceWithHTTPServer(config.DMSconfig{
		Logs: config.BaseConfigLogging{
			Level: config.Info,
		},
		Server: config.HttpServer{
			LogLevel:           config.Info,
			HealthCheckLogging: false,
			Protocol:           config.HTTPS,
			CertFile:           downstreamCertPath,
			KeyFile:            downstreamKeyPath,
			Authentication: config.HttpServerAuthentication{
				MutualTLS: config.HttpServerMutualTLSAuthentication{
					Enabled:        true,
					ValidationMode: config.Request,
				},
			},
		},
		PublisherEventBus:         eventBus.config,
		Storage:                   storageEngine.config,
		DownstreamCertificateFile: downstreamCertPath,
	},
		caTestServer.Service,
		deviceManagerTestServer.Service,
		models.APIServiceInfo{
			Version:   "test",
			BuildSHA:  "-",
			BuildTime: "-",
		})
	if err != nil {
		return nil, fmt.Errorf("could not assemble DMS Manager Service. Exiting: %s", err)
	}

	httpCli := http.Client{}
	httpCli.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	return &DMSManagerTestServer{
		Port:                 port,
		Service:              *svc,
		HttpDeviceManagerSDK: clients.NewHttpDMSManagerClient(&httpCli, fmt.Sprintf("https://127.0.0.1:%d", port)),
		BeforeEach: func() error {
			return nil
		},
		AfterSuite: func() {
			fmt.Println("TEST CLEANUP DMS MANAGER")
		},
	}, nil
}

func BuildVATestServer(caTestServer *CATestServer) (*VATestServer, error) {
	_, _, port, err := AssembleVAServiceWithHTTPServer(config.VAconfig{
		Logs: config.BaseConfigLogging{
			Level: config.Info,
		},
		Server: config.HttpServer{
			LogLevel:           config.Info,
			HealthCheckLogging: false,
			Protocol:           config.HTTP,
		},
		CAClient: config.CAClient{},
	}, caTestServer.HttpCASDK, models.APIServiceInfo{
		Version:   "test",
		BuildSHA:  "-",
		BuildTime: "-",
	})
	if err != nil {
		return nil, err
	}

	return &VATestServer{
		HttpServerURL: fmt.Sprintf("http://127.0.0.1:%d", port),
		CaSDK:         caTestServer.HttpCASDK,
		BeforeEach: func() error {
			return nil
		},
		AfterSuite: func() {
			fmt.Println("TEST CLEANUP VA")
		},
	}, nil
}

func AssembleServices(storageEngine *TestStorageEngineConfig, eventBus *TestEventBusConfig, cryptoEngines *TestCryptoEngineConfig, services []Service) (*TestServer, error) {
	servicesMap := make(map[Service]interface{})

	beforeEachActions := []func() error{}
	afterSuiteActions := []func(){}

	caTestServer, err := BuildCATestServer(storageEngine, cryptoEngines, eventBus)
	servicesMap[CA] = caTestServer
	if err != nil {
		return nil, fmt.Errorf("could not build CATestServer: %s", err)
	}

	beforeEachActions = append(beforeEachActions, caTestServer.BeforeEach)
	afterSuiteActions = append(afterSuiteActions, caTestServer.AfterSuite)

	if slices.Contains(services, DEVICE_MANAGER) {
		deviceManagerTestServer, err := BuildDeviceManagerServiceTestServer(storageEngine, eventBus, caTestServer)
		if err != nil {
			return nil, fmt.Errorf("could not build DeviceManagerTestServer: %s", err)
		}
		servicesMap[DEVICE_MANAGER] = deviceManagerTestServer
		beforeEachActions = append(beforeEachActions, deviceManagerTestServer.BeforeEach)
		afterSuiteActions = append(afterSuiteActions, deviceManagerTestServer.AfterSuite)
	}

	if slices.Contains(services, DMS_MANAGER) {
		deviceTestServerIface, exists := servicesMap[DEVICE_MANAGER]
		if !exists {
			return nil, fmt.Errorf("could not get DeviceManagerTestServer. Make sure to also enable it")
		}

		deviceTestServer, validCasting := deviceTestServerIface.(*DeviceManagerTestServer)
		if !validCasting {
			return nil, fmt.Errorf("could not cast supposed DeviceManagerTestServer. Make sure it was created correctly")
		}

		dmsManagerTestServer, err := BuildDMSManagerServiceTestServer(storageEngine, eventBus, caTestServer, deviceTestServer)
		if err != nil {
			return nil, fmt.Errorf("could not build DMSManagerTestServer: %s", err)
		}
		servicesMap[DMS_MANAGER] = dmsManagerTestServer
		beforeEachActions = append(beforeEachActions, dmsManagerTestServer.BeforeEach)
		afterSuiteActions = append(afterSuiteActions, dmsManagerTestServer.AfterSuite)
	}

	if slices.Contains(services, VA) {
		vaTestServer, err := BuildVATestServer(caTestServer)
		if err != nil {
			return nil, fmt.Errorf("could not build VATestServer: %s", err)
		}
		servicesMap[VA] = vaTestServer
		beforeEachActions = append(beforeEachActions, vaTestServer.BeforeEach)
		afterSuiteActions = append(afterSuiteActions, vaTestServer.AfterSuite)
	}

	if eventBus.BeforeEach != nil {
		beforeEachActions = append(beforeEachActions, eventBus.BeforeEach)
	}
	if eventBus.AfterSuite != nil {
		afterSuiteActions = append(afterSuiteActions, eventBus.AfterSuite)
	}

	if storageEngine.BeforeEach != nil {
		beforeEachActions = append(beforeEachActions, storageEngine.BeforeEach)
	}
	if storageEngine.AfterSuite != nil {
		afterSuiteActions = append(afterSuiteActions, storageEngine.AfterSuite)
	}

	if cryptoEngines != nil {
		if cryptoEngines.BeforeEach != nil {
			beforeEachActions = append(beforeEachActions, cryptoEngines.BeforeEach)
		}
		if cryptoEngines.AfterSuite != nil {
			afterSuiteActions = append(afterSuiteActions, cryptoEngines.AfterSuite)
		}
	}

	beforeEach := func() error {
		for _, action := range beforeEachActions {
			err := action()
			if err != nil {
				return err
			}
		}
		return nil
	}

	afterSuite := func() {
		for _, action := range afterSuiteActions {
			if action != nil {
				action()
			}
		}
	}

	return &TestServer{
		EventBus: eventBus,
		CA:       caTestServer,
		DeviceManager: func() *DeviceManagerTestServer {
			if servicesMap[DEVICE_MANAGER] != nil {
				return servicesMap[DEVICE_MANAGER].(*DeviceManagerTestServer)
			}
			return nil
		}(),
		DMSManager: func() *DMSManagerTestServer {
			if servicesMap[DMS_MANAGER] != nil {
				return servicesMap[DMS_MANAGER].(*DMSManagerTestServer)
			}
			return nil
		}(),
		VA: func() *VATestServer {
			if servicesMap[VA] != nil {
				return servicesMap[VA].(*VATestServer)
			}
			return nil
		}(),
		BeforeEach: beforeEach,
		AfterSuite: afterSuite,
	}, nil
}
