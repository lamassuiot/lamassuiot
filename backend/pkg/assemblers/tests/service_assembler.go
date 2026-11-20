package tests

import (
	"context"
	"crypto/elliptic"
	"fmt"
	"log"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sync/atomic"
	"testing"
	"time"
	"uuid"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/assemblers"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/config"
	authzapi "github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/api"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/api/dto"
	authzconfig "github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/config"
	authzmodels "github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/models"
	authzsdk "github.com/lamassuiot/lamassuiot/v4/connectors/authz/sdk"
	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/lamassuiot/lamassuiot/v4/sdk"
	"github.com/lamassuiot/lamassuiot/v4/shared/subsystems/pkg/test/subsystems"
	"gorm.io/gorm"
)

type TestServiceBuilder struct {
	withEventBus         bool
	withVault            bool
	withDatabase         []string
	withMonitor          bool
	withService          []Service
	withSmtp             *config.SMTPServer
	allowCascadeDelete   bool
	cascadeDeleteExplSet bool
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

func (b TestServiceBuilder) WithSmtp(smtp *config.SMTPServer) TestServiceBuilder {
	b.withSmtp = smtp
	return b
}

func (b TestServiceBuilder) WithCascadeDelete(allow bool) TestServiceBuilder {
	b.allowCascadeDelete = allow
	b.cascadeDeleteExplSet = true
	return b
}

func (b TestServiceBuilder) Build(t *testing.T) (*TestServer, error) {
	var err error
	eventBusConf := &TestEventBusConfig{
		Config: cconfig.EventBusEngine{
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

	testServer, err := AssembleServices(storageConfig, eventBusConf, cryptoConfig, b.withSmtp, b.withService, b.withMonitor, b.allowCascadeDelete)
	if err != nil {
		t.Fatalf("could not assemble Server with HTTP server: %s", err)
	}

	t.Cleanup(testServer.AfterSuite)

	return testServer, nil
}

func (b TestServiceBuilder) BuildSuite() (*TestServer, error) {
	var err error
	eventBusConf := &TestEventBusConfig{
		Config: cconfig.EventBusEngine{
			Enabled: false,
		},
	}
	if b.withEventBus {
		eventBusConf, err = PrepareRabbitMQForTest()
		if err != nil {
			return nil, fmt.Errorf("could not prepare RabbitMQ test server: %s", err)
		}
	}

	storageConfig, err := PreparePostgresForTest(b.withDatabase)
	if err != nil {
		return nil, fmt.Errorf("could not prepare Postgres test server: %s", err)
	}

	cryptoEngines := []CryptoEngine{GOLANG}
	if b.withVault {
		cryptoEngines = append(cryptoEngines, VAULT)
	}

	cryptoConfig := PrepareCryptoEnginesForTest(cryptoEngines)

	if b.withService == nil {
		b.withService = []Service{CA}
	}

	return AssembleServices(storageConfig, eventBusConf, cryptoConfig, b.withSmtp, b.withService, b.withMonitor, b.allowCascadeDelete)
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
	KMS
	CA
	DEVICE_MANAGER
	VA
	DMS_MANAGER
	ALERTS
	AUTHZ
)

type TestEventBusConfig struct {
	Config     cconfig.EventBusEngine
	BeforeEach func() error
	AfterSuite func()
}

type TestStorageEngineConfig struct {
	Config     cconfig.PluggableStorageEngine
	BeforeEach func() error
	AfterSuite func()
}

type TestCryptoEngineConfig struct {
	Config     config.CryptoEngines
	BeforeEach func() error
	AfterSuite func()
}

type KMSTestServer struct {
	Service    services.KMSService
	HttpKMSSDK services.KMSService
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
	KMS           *KMSTestServer
	CA            *CATestServer
	VA            *VATestServer
	DeviceManager *DeviceManagerTestServer
	DMSManager    *DMSManagerTestServer
	Alerts        *AlertsTestServer
	Authz         *AuthzTestServer

	EventBus      *TestEventBusConfig
	Storage       *TestStorageEngineConfig
	CryptoEngines *TestCryptoEngineConfig

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
		Config:     backend.Config.(cconfig.EventBusEngine),
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
		Config:     backend.Config.(cconfig.PluggableStorageEngine),
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

	fsid := fmt.Sprintf("/tmp/%s", uuid.NewV7().String())

	fsconfig := cconfig.CryptoEngineConfig{
		ID:       "filesystem-1",
		Metadata: map[string]any{},
		Type:     cconfig.FilesystemProvider,
		Config: map[string]any{
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
		Config:     cryptoEngineConf,
		BeforeEach: beforeEach,
		AfterSuite: afterSuite,
	}
}

func BuildKMSTestServer(storageEngine *TestStorageEngineConfig, cryptoEngines *TestCryptoEngineConfig, eventBus *TestEventBusConfig, monitor bool, allowCascadeDelete bool) (*KMSTestServer, error) {
	storageEngine.Config.LogLevel = cconfig.Trace

	svc, port, err := assemblers.AssembleKMSServiceWithHTTPServer(config.KMSConfig{
		Logs: cconfig.Logging{
			Level: cconfig.Debug,
		},
		Server: cconfig.HttpServer{
			LogLevel:           cconfig.Debug,
			HealthCheckLogging: false,
			Protocol:           cconfig.HTTP,
		},
		CryptoEngineConfig: cryptoEngines.Config,
		PublisherEventBus:  eventBus.Config,
		Storage:            storageEngine.Config,
	}, models.APIServiceInfo{
		Version:   "test",
		BuildSHA:  "-",
		BuildTime: "-",
	})

	if err != nil {
		return nil, fmt.Errorf("could not assemble KMS with HTTP server: %s", err)
	}

	return &KMSTestServer{
		Service:    *svc,
		HttpKMSSDK: sdk.NewHttpKMSClient(NewTestHTTPClient(), fmt.Sprintf("http://127.0.0.1:%d", port)),
		BeforeEach: func() error {
			return nil
		},
		AfterSuite: func() {},
	}, nil
}

func BuildCATestServer(storageEngine *TestStorageEngineConfig, eventBus *TestEventBusConfig, monitor bool, allowCascadeDelete bool, kmsTestServer KMSTestServer) (*CATestServer, error) {
	storageEngine.Config.LogLevel = cconfig.Trace

	svc, scheduler, port, err := assemblers.AssembleCAServiceWithHTTPServer(config.CAConfig{
		Logs: cconfig.Logging{
			Level: cconfig.Debug,
		},
		Server: cconfig.HttpServer{
			LogLevel:           cconfig.Debug,
			HealthCheckLogging: false,
			Protocol:           cconfig.HTTP,
		},
		PublisherEventBus: eventBus.Config,
		Storage:           storageEngine.Config,
		CertificateMonitoringJob: cconfig.MonitoringJob{
			Enabled:   monitor,
			Frequency: "1s",
		},
		VAServerDomains:    []string{"dev.lamassu.test/api/va"},
		AllowCascadeDelete: allowCascadeDelete,
	}, kmsTestServer.HttpKMSSDK, models.APIServiceInfo{
		Version:   "test",
		BuildSHA:  "-",
		BuildTime: "-",
	})

	if err != nil {
		return nil, fmt.Errorf("could not assemble CA with HTTP server: %s", err)
	}

	return &CATestServer{
		Service:   *svc,
		HttpCASDK: sdk.NewHttpCAClient(NewTestHTTPClient(), fmt.Sprintf("http://127.0.0.1:%d", port)),
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
	svc, port, err := assemblers.AssembleDeviceManagerServiceWithHTTPServer(config.DeviceManagerConfig{
		Logs: cconfig.Logging{
			Level: cconfig.Info,
		},
		Server: cconfig.HttpServer{
			LogLevel:           cconfig.Info,
			HealthCheckLogging: false,
			Protocol:           cconfig.HTTP,
		},
		PublisherEventBus:     eventBus.Config,
		SubscriberDLQEventBus: getDlqEventBusConfig(eventBus.Config),
		SubscriberEventBus:    eventBus.Config,
		Storage:               storageEngine.Config,
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
		HttpDeviceManagerSDK: sdk.NewHttpDeviceManagerClient(NewTestHTTPClient(), fmt.Sprintf("http://127.0.0.1:%d", port)),
		BeforeEach: func() error {
			return nil
		},
		AfterSuite: func() {
			fmt.Println("TEST CLEANUP DEVICE MANAGER")
		},
	}, nil
}

func BuildDMSManagerServiceTestServer(storageEngine *TestStorageEngineConfig, eventBus *TestEventBusConfig, caTestServer *CATestServer, deviceManagerTestServer *DeviceManagerTestServer, authzTestServer *AuthzTestServer) (*DMSManagerTestServer, error) {
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

	var authzClient *authzsdk.Client
	var authzPrincipals config.DMSAuthzPrincipals
	if authzTestServer != nil {
		authzClient = authzTestServer.Client
		authzPrincipals = config.DMSAuthzPrincipals{
			Enabled:                  true,
			PolicyIDs:                append(slices.Clone(AuthzTestPolicyIDs), AuthzTestPolicyIDs[0]), // a repeated id must not break the sync
			SubjectAttributeMappings: map[string]string{"device_id": "x509.subject.cn"},
		}
	}

	svc, port, err := assemblers.AssembleDMSManagerServiceWithHTTPServer(config.DMSconfig{
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
		PublisherEventBus:         eventBus.Config,
		Storage:                   storageEngine.Config,
		DownstreamCertificateFile: downstreamCertPath,
		AuthzPrincipals:           authzPrincipals,
	},
		caTestServer.HttpCASDK,
		deviceManagerTestServer.Service,
		authzClient,
		models.APIServiceInfo{
			Version:   "test",
			BuildSHA:  "-",
			BuildTime: "-",
		})
	if err != nil {
		return nil, fmt.Errorf("could not assemble DMS Manager Service. Exiting: %s", err)
	}

	return &DMSManagerTestServer{
		Port:                 port,
		Service:              *svc,
		HttpDeviceManagerSDK: sdk.NewHttpDMSManagerClient(NewTestHTTPClientInsecure(), fmt.Sprintf("https://127.0.0.1:%d", port)),
		BeforeEach: func() error {
			return nil
		},
		AfterSuite: func() {
			fmt.Println("TEST CLEANUP DMS MANAGER")
		},
	}, nil
}

// AuthzTestPolicyIDs are the policies the DMS Manager test server grants to the principal of an RA.
var AuthzTestPolicyIDs = []string{"policy-a", "policy-b"}

type AuthzTestServer struct {
	Client     *authzsdk.Client // as the DMS Manager sees authz, through FailWhen
	DB         *gorm.DB         // direct access to the authz tables, for states the API cannot create
	failWhen   atomic.Pointer[func(*http.Request) bool]
	BeforeEach func() error
	AfterSuite func()
}

// FailWhen makes authz answer 503 to the matching requests until the next BeforeEach.
func (s *AuthzTestServer) FailWhen(match func(*http.Request) bool) {
	s.failWhen.Store(&match)
}

func BuildAuthzTestServer(storageEngine *TestStorageEngineConfig) (*AuthzTestServer, error) {
	dbConfig := maps.Clone(storageEngine.Config.Config)
	dbConfig["database"], dbConfig["schema"] = "pki", "authz"
	authzDB := cconfig.PluggableStorageEngine{LogLevel: cconfig.Info, Provider: cconfig.Postgres, Config: dbConfig}

	_, _, _, _, port, err := authzapi.AssembleAuthzServiceWithHTTPServer(authzconfig.AuthzConfig{
		Logs:                  cconfig.Logging{Level: cconfig.Info},
		Server:                cconfig.HttpServer{LogLevel: cconfig.Info, Protocol: cconfig.HTTP},
		AuthzDB:               authzDB,
		InsecureSkipJWTVerify: true,
	}, models.APIServiceInfo{Version: "test", BuildSHA: "-", BuildTime: "-"})
	if err != nil {
		return nil, fmt.Errorf("could not assemble Authz Service. Exiting: %s", err)
	}
	db, err := authzapi.CreatePostgresDBConnection(chelpers.SetupLogger(cconfig.Info, "Test Case", "Authz DB"), authzDB)
	if err != nil {
		return nil, fmt.Errorf("could not connect to the Authz database: %s", err)
	}

	srv := &AuthzTestServer{DB: db}
	proxy := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", port)})
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if match := srv.failWhen.Load(); match != nil && (*match)(r) {
			http.Error(w, "injected authz failure", http.StatusServiceUnavailable)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	srv.Client = authzsdk.NewClientWithHTTPClient(sdk.HttpClientWithCustomHeaders(&http.Client{}, "X-Principal-ID", "admin-mode"), front.URL)
	srv.BeforeEach = func() error {
		srv.failWhen.Store(nil)
		if err := db.Exec("TRUNCATE principal_policies, principals, policies CASCADE").Error; err != nil {
			return fmt.Errorf("could not reset the Authz database: %s", err)
		}
		for _, id := range AuthzTestPolicyIDs {
			rules := []*authzmodels.Rule{{Namespace: "iot", SchemaName: "public", EntityType: "organization", Actions: []string{"read"}}}
			if _, err := srv.Client.Policies.Create(context.Background(), &dto.CreatePolicyRequest{ID: id, Name: id, Rules: rules}); err != nil {
				return fmt.Errorf("could not create test policy %s: %s", id, err)
			}
		}
		return nil
	}
	srv.AfterSuite = front.Close
	return srv, nil
}

func BuildVATestServer(storageEngine *TestStorageEngineConfig, eventBus *TestEventBusConfig, caTestServer *CATestServer, kmsTestServer *KMSTestServer, monitor bool) (*VATestServer, error) {
	crlSvc, _, port, err := assemblers.AssembleVAServiceWithHTTPServer(config.VAconfig{
		Logs: cconfig.Logging{
			Level: cconfig.Info,
		},
		Storage: storageEngine.Config,
		Server: cconfig.HttpServer{
			LogLevel:           cconfig.Debug,
			HealthCheckLogging: false,
			Protocol:           cconfig.HTTP,
		},
		VADomains:             []string{"dev.lamassu.test/api/va"},
		SubscriberEventBus:    eventBus.Config,
		SubscriberDLQEventBus: getDlqEventBusConfig(eventBus.Config),
		PublisherEventBus:     eventBus.Config,
		CAClient:              config.CAClient{},
		CRLMonitoringJob: cconfig.MonitoringJob{
			Enabled:   monitor,
			Frequency: "1s",
		},
		FilesystemStorage: cconfig.FSStorageConfig{
			ID:   "fs",
			Type: cconfig.LocalFilesystem,
			Config: map[string]any{
				"storage_directory": "/tmp/lamassuiot",
			},
		},
	}, caTestServer.HttpCASDK, kmsTestServer.HttpKMSSDK, models.APIServiceInfo{
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
		HttpVASDK:     sdk.NewHttpVAClient(NewTestHTTPClient(), fmt.Sprintf("http://127.0.0.1:%d", port)),
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
	svc, port, err := assemblers.AssembleAlertsServiceWithHTTPServer(config.AlertsConfig{
		Logs: cconfig.Logging{
			Level: cconfig.Info,
		},
		Server: cconfig.HttpServer{
			LogLevel:           cconfig.Info,
			HealthCheckLogging: false,
			Protocol:           cconfig.HTTP,
		},
		SubscriberEventBus:    eventBus.Config,
		SubscriberDLQEventBus: getDlqEventBusConfig(eventBus.Config),
		Storage:               storageEngine.Config,
		SMTPConfig:            *smptConfig,
	}, models.APIServiceInfo{
		Version:   "test",
		BuildSHA:  "-",
		BuildTime: "-",
	})
	if err != nil {
		return nil, err
	}

	return &AlertsTestServer{
		Port:                 port,
		Service:              *svc,
		HttpAlertsManagerSDK: sdk.NewHttpAlertsClient(NewTestHTTPClientInsecure(), fmt.Sprintf("https://127.0.0.1:%d", port)),
		BeforeEach: func() error {
			return nil
		},
		AfterSuite: func() {
			fmt.Println("TEST CLEANUP ALERTS")
		},
	}, nil
}

func AssembleServices(storageEngine *TestStorageEngineConfig, eventBus *TestEventBusConfig, cryptoEngines *TestCryptoEngineConfig, smtpConfig *config.SMTPServer, services []Service, monitor bool, allowCascadeDelete bool) (*TestServer, error) {
	servicesMap := make(map[Service]any)

	beforeEachActions := []func() error{}
	afterSuiteActions := []func(){}

	kmsTestServer, err := BuildKMSTestServer(storageEngine, cryptoEngines, eventBus, monitor, allowCascadeDelete)
	servicesMap[KMS] = kmsTestServer
	if err != nil {
		return nil, fmt.Errorf("could not build KMSTestServer: %s", err)
	}

	beforeEachActions = append(beforeEachActions, kmsTestServer.BeforeEach)
	afterSuiteActions = append(afterSuiteActions, kmsTestServer.AfterSuite)

	caTestServer, err := BuildCATestServer(storageEngine, eventBus, monitor, allowCascadeDelete, *kmsTestServer)
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

	if slices.Contains(services, AUTHZ) {
		authzTestServer, err := BuildAuthzTestServer(storageEngine)
		if err != nil {
			return nil, fmt.Errorf("could not build AuthzTestServer: %s", err)
		}
		servicesMap[AUTHZ] = authzTestServer
		beforeEachActions = append(beforeEachActions, authzTestServer.BeforeEach)
		afterSuiteActions = append(afterSuiteActions, authzTestServer.AfterSuite)
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

		authzTestServer, _ := servicesMap[AUTHZ].(*AuthzTestServer)
		dmsManagerTestServer, err := BuildDMSManagerServiceTestServer(storageEngine, eventBus, caTestServer, deviceTestServer, authzTestServer)
		if err != nil {
			return nil, fmt.Errorf("could not build DMSManagerTestServer: %s", err)
		}
		servicesMap[DMS_MANAGER] = dmsManagerTestServer
		beforeEachActions = append(beforeEachActions, dmsManagerTestServer.BeforeEach)
		afterSuiteActions = append(afterSuiteActions, dmsManagerTestServer.AfterSuite)
	}

	if slices.Contains(services, VA) {
		vaTestServer, err := BuildVATestServer(storageEngine, eventBus, caTestServer, kmsTestServer, monitor)
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
		EventBus:      eventBus,
		Storage:       storageEngine,
		CryptoEngines: cryptoEngines,
		KMS:           kmsTestServer,
		CA:            caTestServer,
		DeviceManager: func() *DeviceManagerTestServer {
			if servicesMap[DEVICE_MANAGER] != nil {
				return servicesMap[DEVICE_MANAGER].(*DeviceManagerTestServer)
			}
			return nil
		}(),
		Authz: func() *AuthzTestServer {
			if servicesMap[AUTHZ] != nil {
				return servicesMap[AUTHZ].(*AuthzTestServer)
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
	for range retry {
		err = f()
		if err == nil {
			return nil
		}

		time.Sleep(sleep)
	}

	return fmt.Errorf("could not execute function after %d retries. Last error: %s", retry, err)
}

func getDlqEventBusConfig(conf cconfig.EventBusEngine) cconfig.EventBusEngine {
	dlqEventBus := conf
	if conf.Config != nil {
		dlqEventBus.Config = deepCopy(conf.Config)
		dlqEventBus.Config["exchange"] = "lamassu-dlq"
	}

	return dlqEventBus
}

func deepCopy(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	dst := make(map[string]any, len(src))
	maps.Copy(dst, src)
	return dst
}

func StartWebhookServer() (*gin.Engine, string, func(), error) {
	// Create a custom HTTP handler
	router := gin.Default()

	// Listen on a random free port
	listener, err := net.Listen("tcp", ":0") // :0 to choose a random port
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to listen on a random port: %w", err)
	}

	addr := listener.Addr().String()
	re := regexp.MustCompile(`:(\d+)$`)
	match := re.FindStringSubmatch(addr)
	var port string
	if len(match) > 1 {
		port = ":" + match[1] // Capture group 1
	}

	url := fmt.Sprintf("http://localhost%s", port)

	// Create an HTTP server
	server := &http.Server{
		Handler: router,
	}

	go func() {
		if err := server.Serve(listener); err != nil {
			log.Printf("Server error: %v", err)
		}
	}()

	shutdown := func() {
		log.Println("Shutting down the server...")
		if err := server.Shutdown(context.Background()); err != nil {
			log.Printf("Server forced to shutdown: %v", err)
		}
	}

	return router, url, shutdown, nil
}
