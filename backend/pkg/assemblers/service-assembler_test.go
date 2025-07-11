package assemblers

import (
	"crypto/elliptic"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/sdk/v3"
	"github.com/lamassuiot/lamassuiot/shared/subsystems/v3/pkg/test/subsystems"
)

type TestServiceBuilder struct {
	withEventBus bool
	withVault    bool
	withDatabase []string
	withMonitor  bool
	withService  []Service
	withSmtp     *config.SMTPServer
}

func (b TestServiceBuilder) WithEventBus() TestServiceBuilder {
	b.withEventBus = true
	return b
}

func (b TestServiceBuilder) WithVault() TestServiceBuilder {
	b.withVault = true
	return b
}

func (b TestServiceBuilder) WithDatabase(dbs ...string) TestServiceBuilder {
	b.withDatabase = dbs
	return b
}

func (b TestServiceBuilder) WithMonitor() TestServiceBuilder {
	b.withMonitor = true
	return b
}

func (b TestServiceBuilder) WithService(services ...Service) TestServiceBuilder {
	b.withService = services
	return b
}

func (b TestServiceBuilder) WithSmtp(config *config.SMTPServer) TestServiceBuilder {
	b.withSmtp = config
	return b
}

func (b TestServiceBuilder) Build(t *testing.T) (*TestServer, error) {
	var err error
	eventBusConf := &TestEventBusConfig{
		config: cconfig.EventBusEngine{
			Enabled: false,
		},
	}
	if b.withEventBus {
		eventBusConf, err = PrepareRabbitMQForTest()
		if err != nil {
			t.Fatalf("could not prepare RabbitMQ test server: %s", err)
		}
	}

	storageConfig, err := PreparePostgresForTest(b.withDatabase)
	if err != nil {
		t.Fatalf("could not prepare Postgres test server: %s", err)
	}

	cryptoEngines := []CryptoEngine{GOLANG}
	if b.withVault {
		cryptoEngines = append(cryptoEngines, VAULT)
	}

	cryptoConfig := PrepareCryptoEnginesForTest(cryptoEngines)

	if b.withService == nil {
		b.withService = []Service{CA}
	}

	testServer, err := AssembleServices(storageConfig, eventBusConf, cryptoConfig, b.withSmtp, b.withService, b.withMonitor)
	if err != nil {
		t.Fatalf("could not assemble Server with HTTP server: %s", err)
	}

	t.Cleanup(testServer.AfterSuite)

	return testServer, nil
}

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
	ALERTS
)

type TestEventBusConfig struct {
	config     cconfig.EventBusEngine
	BeforeEach func() error
	AfterSuite func()
}

type TestStorageEngineConfig struct {
	config     cconfig.PluggableStorageEngine
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
	CRLService    services.CRLService
	HttpCASDK     services.CAService
	HttpVASDK     services.VAService
	BeforeEach    func() error
	AfterSuite    func()
}

type AlertsTestServer struct {
	Port                 int
	Service              services.AlertsService
	HttpAlertsManagerSDK services.AlertsService
	BeforeEach           func() error
	AfterSuite           func()
}

type TestServer struct {
	CA            *CATestServer
	VA            *VATestServer
	DeviceManager *DeviceManagerTestServer
	DMSManager    *DMSManagerTestServer
	Alerts        *AlertsTestServer

	EventBus *TestEventBusConfig

	BeforeEach func() error
	AfterSuite func()
}

func PrepareRabbitMQForTest() (*TestEventBusConfig, error) {
	rabbitmqSubsystem := subsystems.GetSubsystemBuilder[subsystems.Subsystem](subsystems.RabbitMQ)

	backend, err := rabbitmqSubsystem.Run(false)
	if err != nil {
		return nil, err
	}

	return &TestEventBusConfig{
		config:     backend.Config.(cconfig.EventBusEngine),
		AfterSuite: backend.AfterSuite,
		BeforeEach: backend.BeforeEach,
	}, nil

}

func PreparePostgresForTest(dbs []string) (*TestStorageEngineConfig, error) {
	postgresSubsystem := subsystems.GetSubsystemBuilder[subsystems.StorageSubsystem](subsystems.Postgres)

	postgresSubsystem.Prepare(dbs)
	backend, err := postgresSubsystem.Run(false)
	if err != nil {
		return nil, err
	}

	return &TestStorageEngineConfig{
		config:     backend.Config.(cconfig.PluggableStorageEngine),
		BeforeEach: backend.BeforeEach,
		AfterSuite: backend.AfterSuite,
	}, nil

}

func PrepareCryptoEnginesForTest(engines []CryptoEngine) *TestCryptoEngineConfig {
	beforeEachActions := []func() error{}
	afterSuiteActions := []func(){}

	cryptoEngineConf := config.CryptoEngines{
		LogLevel:          cconfig.Info,
		DefaultEngine:     "filesystem-1",
		MigrateKeysFormat: true,
		CryptoEngines:     []cconfig.CryptoEngineConfig{},
	}

	fsid := fmt.Sprintf("/tmp/%s", uuid.NewString())

	fsconfig := cconfig.CryptoEngineConfig{
		ID:       "filesystem-1",
		Metadata: map[string]interface{}{},
		Type:     cconfig.FilesystemProvider,
		Config: map[string]interface{}{
			"storage_directory": fsid,
		},
	}

	cryptoEngineConf.CryptoEngines = append(cryptoEngineConf.CryptoEngines, fsconfig)

	beforeEachActions = append(beforeEachActions, func() error {
		return nil
	})
	afterSuiteActions = append(afterSuiteActions, func() {
		os.RemoveAll(fsid)
	})

	if slices.Contains(engines, VAULT) {

		backend, err := subsystems.GetSubsystemBuilder[subsystems.Subsystem](subsystems.Vault).Run(false)
		if err != nil {
			panic(fmt.Sprintf("could not run Vault subsystem: %s", err))
		}

		cryptoEngineConf.CryptoEngines = append(cryptoEngineConf.CryptoEngines, backend.Config.(cconfig.CryptoEngineConfig))

		beforeEachActions = append(beforeEachActions, backend.BeforeEach)
		afterSuiteActions = append(afterSuiteActions, backend.AfterSuite)
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

func BuildCATestServer(storageEngine *TestStorageEngineConfig, cryptoEngines *TestCryptoEngineConfig, eventBus *TestEventBusConfig, monitor bool) (*CATestServer, error) {
	storageEngine.config.LogLevel = cconfig.Trace

	svc, scheduler, port, err := AssembleCAServiceWithHTTPServer(config.CAConfig{
		Logs: cconfig.Logging{
			Level: cconfig.Debug,
		},
		Server: cconfig.HttpServer{
			LogLevel:           cconfig.Debug,
			HealthCheckLogging: false,
			Protocol:           cconfig.HTTP,
		},
		PublisherEventBus:  eventBus.config,
		Storage:            storageEngine.config,
		CryptoEngineConfig: cryptoEngines.config,
		CertificateMonitoringJob: cconfig.MonitoringJob{
			Enabled:   monitor,
			Frequency: "1s",
		},
		VAServerDomains: []string{"dev.lamassu.test/api/va"},
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
		HttpCASDK: sdk.NewHttpCAClient(http.DefaultClient, fmt.Sprintf("http://127.0.0.1:%d", port)),
		BeforeEach: func() error {
			return nil
		},
		AfterSuite: func() {
			if scheduler != nil {
				scheduler.Stop()
			}
		},
	}, nil
}

func BuildDeviceManagerServiceTestServer(storageEngine *TestStorageEngineConfig, eventBus *TestEventBusConfig, caTestServer *CATestServer) (*DeviceManagerTestServer, error) {
	svc, port, err := AssembleDeviceManagerServiceWithHTTPServer(config.DeviceManagerConfig{
		Logs: cconfig.Logging{
			Level: cconfig.Info,
		},
		Server: cconfig.HttpServer{
			LogLevel:           cconfig.Info,
			HealthCheckLogging: false,
			Protocol:           cconfig.HTTP,
		},
		PublisherEventBus:  eventBus.config,
		SubscriberEventBus: eventBus.config,
		Storage:            storageEngine.config,
	}, caTestServer.HttpCASDK, models.APIServiceInfo{
		Version:   "test",
		BuildSHA:  "-",
		BuildTime: "-",
	})
	if err != nil {
		return nil, fmt.Errorf("could not assemble Device Manager Service. Exiting: %s", err)
	}

	return &DeviceManagerTestServer{
		Service:              *svc,
		HttpDeviceManagerSDK: sdk.NewHttpDeviceManagerClient(http.DefaultClient, fmt.Sprintf("http://127.0.0.1:%d", port)),
		BeforeEach: func() error {
			return nil
		},
		AfterSuite: func() {
			fmt.Println("TEST CLEANUP DEVICE MANAGER")
		},
	}, nil
}

func BuildDMSManagerServiceTestServer(storageEngine *TestStorageEngineConfig, eventBus *TestEventBusConfig, caTestServer *CATestServer, deviceManagerTestServer *DeviceManagerTestServer) (*DMSManagerTestServer, error) {
	key, _ := chelpers.GenerateECDSAKey(elliptic.P256())
	crt, _ := chelpers.GenerateSelfSignedCertificate(key, "downstream")
	downstreamPath := fmt.Sprintf("/tmp/%s", crt.SerialNumber.String())
	downstreamCertPath := fmt.Sprintf("%s.crt", downstreamPath)
	downstreamKeyPath := fmt.Sprintf("%s.key", downstreamPath)

	crtPem := chelpers.CertificateToPEM(crt)
	err := os.WriteFile(downstreamCertPath, []byte(crtPem), 0600)
	if err != nil {
		return nil, fmt.Errorf("could not save downstream cert. Exiting: %s", err)
	}

	keyPem, _ := chelpers.PrivateKeyToPEM(key)
	err = os.WriteFile(downstreamKeyPath, []byte(keyPem), 0600)
	if err != nil {
		return nil, fmt.Errorf("could not save downstream cert. Exiting: %s", err)
	}

	svc, port, err := AssembleDMSManagerServiceWithHTTPServer(config.DMSconfig{
		Logs: cconfig.Logging{
			Level: cconfig.Info,
		},
		Server: cconfig.HttpServer{
			LogLevel:           cconfig.Info,
			HealthCheckLogging: false,
			Protocol:           cconfig.HTTPS,
			CertFile:           downstreamCertPath,
			KeyFile:            downstreamKeyPath,
			Authentication: cconfig.HttpServerAuthentication{
				MutualTLS: cconfig.HttpServerMutualTLSAuthentication{
					Enabled:        true,
					ValidationMode: cconfig.Request,
				},
			},
		},
		PublisherEventBus:         eventBus.config,
		Storage:                   storageEngine.config,
		DownstreamCertificateFile: downstreamCertPath,
	},
		caTestServer.HttpCASDK,
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
		HttpDeviceManagerSDK: sdk.NewHttpDMSManagerClient(&httpCli, fmt.Sprintf("https://127.0.0.1:%d", port)),
		BeforeEach: func() error {
			return nil
		},
		AfterSuite: func() {
			fmt.Println("TEST CLEANUP DMS MANAGER")
		},
	}, nil
}

func BuildVATestServer(storageEngine *TestStorageEngineConfig, eventBus *TestEventBusConfig, caTestServer *CATestServer, monitor bool) (*VATestServer, error) {
	crlSvc, _, port, err := AssembleVAServiceWithHTTPServer(config.VAconfig{
		Logs: cconfig.Logging{
			Level: cconfig.Info,
		},
		Storage: storageEngine.config,
		Server: cconfig.HttpServer{
			LogLevel:           cconfig.Debug,
			HealthCheckLogging: false,
			Protocol:           cconfig.HTTP,
		},
		SubscriberEventBus: eventBus.config,
		PublisherEventBus:  eventBus.config,
		CAClient:           config.CAClient{},
		CRLMonitoringJob: cconfig.MonitoringJob{
			Enabled:   monitor,
			Frequency: "1s",
		},
		FilesystemStorage: cconfig.FSStorageConfig{
			ID:   "fs",
			Type: cconfig.LocalFilesystem,
			Config: map[string]interface{}{
				"storage_directory": "/tmp/lamassuiot",
			},
		},
	}, caTestServer.HttpCASDK, models.APIServiceInfo{
		Version:   "test",
		BuildSHA:  "-",
		BuildTime: "-",
	})
	if err != nil {
		return nil, err
	}

	return &VATestServer{
		CRLService:    *crlSvc,
		HttpServerURL: fmt.Sprintf("http://127.0.0.1:%d", port),
		HttpCASDK:     caTestServer.HttpCASDK,
		HttpVASDK:     sdk.NewHttpVAClient(http.DefaultClient, fmt.Sprintf("http://127.0.0.1:%d", port)),
		BeforeEach: func() error {
			return nil
		},
		AfterSuite: func() {
			fmt.Println("TEST CLEANUP VA")
		},
	}, nil
}

func BuildAlertsTestServer(storageEngine *TestStorageEngineConfig, eventBus *TestEventBusConfig, smptConfig *config.SMTPServer) (*AlertsTestServer, error) {
	if smptConfig == nil {
		smptConfig = &config.SMTPServer{}
	}
	svc, port, err := AssembleAlertsServiceWithHTTPServer(config.AlertsConfig{
		Logs: cconfig.Logging{
			Level: cconfig.Info,
		},
		Server: cconfig.HttpServer{
			LogLevel:           cconfig.Info,
			HealthCheckLogging: false,
			Protocol:           cconfig.HTTP,
		},
		SubscriberEventBus: eventBus.config,
		Storage:            storageEngine.config,
		SMTPConfig:         *smptConfig,
	}, models.APIServiceInfo{
		Version:   "test",
		BuildSHA:  "-",
		BuildTime: "-",
	})
	if err != nil {
		return nil, err
	}

	httpCli := http.Client{}
	httpCli.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	return &AlertsTestServer{
		Port:                 port,
		Service:              *svc,
		HttpAlertsManagerSDK: sdk.NewHttpAlertsClient(&httpCli, fmt.Sprintf("https://127.0.0.1:%d", port)),
		BeforeEach: func() error {
			return nil
		},
		AfterSuite: func() {
			fmt.Println("TEST CLEANUP ALERTS")
		},
	}, nil
}

func AssembleServices(storageEngine *TestStorageEngineConfig, eventBus *TestEventBusConfig, cryptoEngines *TestCryptoEngineConfig, smtpConfig *config.SMTPServer, services []Service, monitor bool) (*TestServer, error) {
	servicesMap := make(map[Service]interface{})

	beforeEachActions := []func() error{}
	afterSuiteActions := []func(){}

	caTestServer, err := BuildCATestServer(storageEngine, cryptoEngines, eventBus, monitor)
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
		vaTestServer, err := BuildVATestServer(storageEngine, eventBus, caTestServer, monitor)
		if err != nil {
			return nil, fmt.Errorf("could not build VATestServer: %s", err)
		}
		servicesMap[VA] = vaTestServer
		beforeEachActions = append(beforeEachActions, vaTestServer.BeforeEach)
		afterSuiteActions = append(afterSuiteActions, vaTestServer.AfterSuite)
	}

	if slices.Contains(services, ALERTS) {
		alertsTestServer, err := BuildAlertsTestServer(storageEngine, eventBus, smtpConfig)
		if err != nil {
			return nil, fmt.Errorf("could not build AlertsTestServer: %s", err)
		}
		servicesMap[ALERTS] = alertsTestServer
		beforeEachActions = append(beforeEachActions, alertsTestServer.BeforeEach)
		afterSuiteActions = append(afterSuiteActions, alertsTestServer.AfterSuite)
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
		Alerts: func() *AlertsTestServer {
			if servicesMap[ALERTS] != nil {
				return servicesMap[ALERTS].(*AlertsTestServer)
			}
			return nil
		}(),
		BeforeEach: beforeEach,
		AfterSuite: afterSuite,
	}, nil
}

func SleepRetry(retry int, sleep time.Duration, f func() error) error {
	var err error
	for i := 0; i < retry; i++ {
		err = f()
		if err == nil {
			return nil
		}

		time.Sleep(sleep)
	}

	return fmt.Errorf("could not execute function after %d retries. Last error: %s", retry, err)
}
