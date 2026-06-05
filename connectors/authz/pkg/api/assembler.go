package api

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	authzconfig "github.com/lamassuiot/authz/pkg/config"
	"github.com/lamassuiot/authz/pkg/engine"
	authzmodels "github.com/lamassuiot/authz/pkg/models"
	authzmw_audit "github.com/lamassuiot/authz/pkg/middlewares/audit"
	authzmw_eventpub "github.com/lamassuiot/authz/pkg/middlewares/eventpub"
	"github.com/lamassuiot/authz/pkg/service"
	"github.com/lamassuiot/authz/pkg/store"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/eventbus"
	bauditpub "github.com/lamassuiot/lamassuiot/backend/v3/pkg/middlewares/audit"
	beventpub "github.com/lamassuiot/lamassuiot/backend/v3/pkg/middlewares/eventpub"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	sdk "github.com/lamassuiot/lamassuiot/sdk/v3"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const serviceID = "authz"

func AssembleAuthzServiceWithHTTPServer(conf authzconfig.AuthzConfig, serviceInfo models.APIServiceInfo) (*service.PrincipalManager, *engine.Engine, *service.PolicyManager, *service.IdentityResolver, int, error) {
	principalManager, eng, policyManager, resolver, err := AssembleAuthzService(conf)
	if err != nil {
		return nil, nil, nil, nil, -1, fmt.Errorf("failed to assemble Authz service: %w", err)
	}

	lSvc := helpers.SetupLogger(conf.Logs.Level, "AUTHZ", "Service")
	httpLogLevel := conf.Server.LogLevel
	if httpLogLevel == "" {
		httpLogLevel = conf.Logs.Level
	}
	lHttp := helpers.SetupLogger(httpLogLevel, "AUTHZ", "HTTP Server")

	// Build authz engine from concrete managers BEFORE any wrapping so it always
	// holds real storage references (the engine uses principalManager.matchService
	// and principalManager.store which are not exposed by PrincipalService).
	authzEngine := service.NewAuthzService(eng, principalManager, policyManager, service.WithServiceLogger(lSvc))

	// Apply event/audit publisher decorators conditionally.
	var principalSvc service.PrincipalService = principalManager
	var policySvc service.PolicyService = policyManager

	if conf.PublisherEventBus.Enabled {
		lMessaging := helpers.SetupLogger(conf.PublisherEventBus.LogLevel, "AUTHZ", "Event Bus")
		lAudit := helpers.SetupLogger(conf.PublisherEventBus.LogLevel, "AUTHZ", "Audit Bus")

		pub, err := eventbus.NewEventBusPublisher(conf.PublisherEventBus, serviceID, lMessaging)
		if err != nil {
			return nil, nil, nil, nil, -1, fmt.Errorf("could not create Event Bus publisher: %w", err)
		}

		cePub := &beventpub.CloudEventPublisher{Publisher: pub, ServiceID: serviceID, Logger: lMessaging}
		auditCePub := &beventpub.CloudEventPublisher{Publisher: pub, ServiceID: serviceID, Logger: lAudit}
		auditPub := *bauditpub.NewAuditPublisher(auditCePub)

		principalSvc = authzmw_eventpub.NewPrincipalEventPublisher(cePub)(principalManager)
		principalSvc = authzmw_audit.NewPrincipalAuditPublisher(auditPub)(principalSvc)

		policySvc = authzmw_eventpub.NewPolicyEventPublisher(cePub)(policyManager)
		policySvc = authzmw_audit.NewPolicyAuditPublisher(auditPub)(policySvc)

		lMessaging.Infof("Event Bus publisher enabled")
	}

	httpEngine := routes.NewGinEngine(lHttp)
	httpGrp := httpEngine.Group("/")
	NewAuthzRoutes(httpGrp, authzEngine, principalSvc, eng, policySvc, resolver, lHttp)

	port, err := routes.RunHttpRouter(lHttp, httpEngine, conf.Server, serviceInfo)
	if err != nil {
		return nil, nil, nil, nil, -1, fmt.Errorf("failed to start Authz HTTP server: %w", err)
	}

	lHttp.Infof("Authz Service is running on port %d", port)
	return principalManager, eng, policyManager, resolver, port, nil
}

func AssembleAuthzService(conf authzconfig.AuthzConfig) (*service.PrincipalManager, *engine.Engine, *service.PolicyManager, *service.IdentityResolver, error) {
	sdk.InitOtelSDK(context.Background(), "Authz Service", conf.OtelConfig)

	lDB := helpers.SetupLogger(conf.Logs.Level, "AUTHZ", "DB")

	authzDB, err := CreatePostgresDBConnection(lDB, conf.AuthzDB)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to connect to authz database: %w", err)
	}

	policyStore, err := store.NewGormPolicyStore(authzDB)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to create policy store: %w", err)
	}

	principalManager, err := service.NewPrincipalManager(authzDB)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	policyManager := service.NewPolicyManager(policyStore)

	schemaDbs := make(map[string]*gorm.DB)
	for schemaName, credentials := range conf.Credentials {
		lDB.Infof("Creating database connection for schema: %s", schemaName)
		db, err := CreatePostgresDBConnection(lDB, credentials)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to create database connection for schema %s: %w", schemaName, err)
		}
		schemaDbs[schemaName] = db
	}

	lEngine := helpers.SetupLogger(conf.Logs.Level, "AUTHZ", "Engine")

	eng, err := engine.NewEngine(schemaDbs, conf.Schemas, engine.WithLogger(lEngine))
	if err != nil {
		return nil, nil, nil, nil, err
	}

	if conf.PreloadDir != "" {
		lPreload := helpers.SetupLogger(conf.Logs.Level, "AUTHZ", "Preload")
		if err := preloadPolicies(context.Background(), policyManager, conf.PreloadDir, lPreload); err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to preload policies: %w", err)
		}
	}

	if len(conf.Bootstrap) > 0 {
		lBootstrap := helpers.SetupLogger(conf.Logs.Level, "AUTHZ", "Bootstrap")
		if err := runBootstrap(context.Background(), principalManager, conf.Bootstrap, lBootstrap); err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to run bootstrap: %w", err)
		}
	}

	resolver := principalManager.NewIdentityResolver(policyManager)

	return principalManager, eng, policyManager, resolver, nil
}

// preloadPolicies reads all JSON files from dir and creates them as policies if they don't already exist.
func preloadPolicies(ctx context.Context, pm *service.PolicyManager, dir string, log *logrus.Entry) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("failed to read preload directory %q: %w", dir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() || len(entry.Name()) < 5 || entry.Name()[len(entry.Name())-5:] != ".json" {
			continue
		}

		filePath := dir + string(os.PathSeparator) + entry.Name()
		data, err := os.ReadFile(filePath)
		if err != nil {
			log.Warnf("Skipping preload file %s: %v", filePath, err)
			continue
		}

		var policy authzmodels.Policy
		if err := json.Unmarshal(data, &policy); err != nil {
			log.Warnf("Skipping preload file %s: invalid JSON: %v", filePath, err)
			continue
		}

		if !strings.HasPrefix(policy.ID, "lamassu.") {
			policy.ID = "lamassu." + policy.ID
		}

		if err := pm.CreatePolicy(ctx, &policy); err != nil {
			log.Warnf("Skipping preload file %s: %v", filePath, err)
			continue
		}

		log.Infof("Preloaded policy %q (id=%s) from %s", policy.Name, policy.ID, filePath)
	}

	return nil
}

// postgresDBConfig holds the fields extracted from a PluggableStorageEngine config map.
type postgresDBConfig struct {
	Hostname string           `mapstructure:"hostname"`
	Port     int              `mapstructure:"port"`
	Username string           `mapstructure:"username"`
	Password cconfig.Password `mapstructure:"password"`
	Database string           `mapstructure:"database"`
	// Schema sets the PostgreSQL search_path. Used when all services share one
	// database (e.g. monolithic mode where schemas live inside the "pki" DB).
	Schema string `mapstructure:"schema"`
}

func CreatePostgresDBConnection(log *logrus.Entry, cfg cconfig.PluggableStorageEngine) (*gorm.DB, error) {
	dbCfg, err := cconfig.DecodeStruct[postgresDBConfig](cfg.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to decode postgres config: %w", err)
	}

	if dbCfg.Database == "" {
		return nil, fmt.Errorf("postgres config is missing required field 'database'")
	}

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=disable",
		dbCfg.Hostname, dbCfg.Username, string(dbCfg.Password), dbCfg.Database, dbCfg.Port)
	if dbCfg.Schema != "" {
		dsn += " search_path=" + dbCfg.Schema
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: NewGormLogger(log),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)

	log.Infof("Connected to PostgreSQL database: %s@%s:%d/%s", dbCfg.Username, dbCfg.Hostname, dbCfg.Port, dbCfg.Database)
	return db, nil
}
