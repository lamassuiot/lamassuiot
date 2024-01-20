package assemblers

import (
	"fmt"
	"net/http"

	"github.com/lamassuiot/lamassuiot/v2/pkg/clients"
	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage/postgres"
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
	BeforeEach    func() error
	AfterSuite    func()
}

func PreparePostgresForTest(dbs []string) (TestStorageEngineConfig, error) {

	pConfig, postgresEngine := postgres_test.BeforeSuite(dbs)

	return TestStorageEngineConfig{
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
				default:
					return fmt.Errorf("unknown db name: %s", dbName)
				}
			}
			return nil
		},
		AfterSuite: postgresEngine.AfterSuite,
	}, nil
}

func PrepareCryptoEnginesForTest(engines []CryptoEngine) TestCryptoEngineConfig {

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
	afterSuiteActions = append(afterSuiteActions, func() {})

	if contains(engines, VAULT) {
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

	return TestCryptoEngineConfig{
		config:     cryptoEngineConf,
		BeforeEach: beforeEach,
		AfterSuite: afterSuite,
	}
}

func contains[T comparable](slice []T, value T) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}

func BuildCATestServer(storageEngine TestStorageEngineConfig, criptoEngines TestCryptoEngineConfig) (*CATestServer, error) {

	svc, port, err := AssembleCAServiceWithHTTPServer(config.CAConfig{
		BaseConfig: config.BaseConfig{
			Logs: config.BaseConfigLogging{
				Level: config.Info,
			},
			Server: config.HttpServer{
				LogLevel:           config.Info,
				HealthCheckLogging: false,
				Protocol:           config.HTTP,
			},
			EventBus: config.EventBusEngine{Enabled: false},
		},
		Storage:       storageEngine.config,
		CryptoEngines: criptoEngines.config,
		CryptoMonitoring: config.CryptoMonitoring{
			Enabled: false,
		},
		VAServerDomain: "http://dev.lamassu.test",
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
			err := storageEngine.BeforeEach()
			if err != nil {
				return err
			}
			err = criptoEngines.BeforeEach()
			if err != nil {
				return err
			}
			return nil
		},
		AfterSuite: func() {
			storageEngine.AfterSuite()
			criptoEngines.AfterSuite()
		},
	}, nil
}

func BuildDeviceManagerServiceTestServer(storageEngine TestStorageEngineConfig, caCATestServer CATestServer) (*DeviceManagerTestServer, error) {
	svc, port, err := AssembleDeviceManagerServiceWithHTTPServer(config.DeviceManagerConfig{
		BaseConfig: config.BaseConfig{
			Logs: config.BaseConfigLogging{
				Level: config.Info,
			},
			Server: config.HttpServer{
				LogLevel:           config.Info,
				HealthCheckLogging: false,
				Protocol:           config.HTTP,
			},
			EventBus: config.EventBusEngine{Enabled: false},
		},
		Storage: storageEngine.config,
	}, caCATestServer.Service, models.APIServiceInfo{
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
			err := storageEngine.BeforeEach()
			if err != nil {
				return err
			}
			return nil
		},
		AfterSuite: func() {
			fmt.Println("TEST CLEANUP DEVICE MANAGER")
		},
	}, nil
}

func BuildVATestServer(caCATestServer CATestServer) (*VATestServer, error) {
	_, _, port, err := AssembleVAServiceWithHTTPServer(config.VAconfig{
		BaseConfig: config.BaseConfig{
			Logs: config.BaseConfigLogging{
				Level: config.Info,
			},
			Server: config.HttpServer{
				LogLevel:           config.Info,
				HealthCheckLogging: false,
				Protocol:           config.HTTP,
			},
			EventBus: config.EventBusEngine{Enabled: false},
		},
		CAClient: config.CAClient{},
	}, caCATestServer.HttpCASDK, models.APIServiceInfo{
		Version:   "test",
		BuildSHA:  "-",
		BuildTime: "-",
	})
	if err != nil {
		return nil, err
	}

	return &VATestServer{
		HttpServerURL: fmt.Sprintf("http://127.0.0.1:%d", port),
		CaSDK:         caCATestServer.HttpCASDK,
		BeforeEach: func() error {
			err := caCATestServer.BeforeEach()
			if err != nil {
				return fmt.Errorf("could not run CATestServer BeforeEach: %s", err)
			}
			return nil
		},
	}, nil
}

func AssembleSerices(storageEngine TestStorageEngineConfig, criptoEngines TestCryptoEngineConfig, services []Service) (*TestServer, error) {
	servicesMap := make(map[Service]interface{})

	beforeEachActions := []func() error{}
	afterSuiteActions := []func(){}

	caCATestServer, err := BuildCATestServer(storageEngine, criptoEngines)
	servicesMap[CA] = caCATestServer
	if err != nil {
		return nil, fmt.Errorf("could not build CATestServer: %s", err)
	}

	beforeEachActions = append(beforeEachActions, caCATestServer.BeforeEach)
	afterSuiteActions = append(afterSuiteActions, caCATestServer.AfterSuite)

	if contains(services, DEVICE_MANAGER) {
		deviceManagerTestServer, err := BuildDeviceManagerServiceTestServer(storageEngine, *caCATestServer)
		if err != nil {
			return nil, fmt.Errorf("could not build DeviceManagerTestServer: %s", err)
		}
		servicesMap[DEVICE_MANAGER] = deviceManagerTestServer
		beforeEachActions = append(beforeEachActions, deviceManagerTestServer.BeforeEach)
		afterSuiteActions = append(afterSuiteActions, deviceManagerTestServer.AfterSuite)
	}

	if contains(services, VA) {
		vaTestServer, err := BuildVATestServer(*caCATestServer)
		if err != nil {
			return nil, fmt.Errorf("could not build VATestServer: %s", err)
		}
		servicesMap[VA] = vaTestServer
		beforeEachActions = append(beforeEachActions, vaTestServer.BeforeEach)
		afterSuiteActions = append(afterSuiteActions, vaTestServer.AfterSuite)
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
		CA: caCATestServer,
		DeviceManager: func() *DeviceManagerTestServer {
			if servicesMap[DEVICE_MANAGER] != nil {
				return servicesMap[DEVICE_MANAGER].(*DeviceManagerTestServer)
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
