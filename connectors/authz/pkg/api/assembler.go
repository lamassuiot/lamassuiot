package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"time"

	rds "github.com/krotscheck/go-rds-driver"
	rdsgorm "github.com/krotscheck/go-rds-driver/gorm"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/eventbus"
	bauditpub "github.com/lamassuiot/lamassuiot/v4/backend/pkg/middlewares/audit"
	beventpub "github.com/lamassuiot/lamassuiot/v4/backend/pkg/middlewares/eventpub"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/routes"
	authzconfig "github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/engine"
	authzmw_audit "github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/middlewares/audit"
	authzmw_eventpub "github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/middlewares/eventpub"
	authzmw_otel "github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/middlewares/otel"
	authzmodels "github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/service"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/specs"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/store"
	authzgorm "github.com/lamassuiot/lamassuiot/v4/connectors/authz/sdk/gorm"
	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	storagepostgres "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	postgresconfig "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/config"
	sdk "github.com/lamassuiot/lamassuiot/v4/sdk"
	"github.com/sirupsen/logrus"
	gormpostgres "gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
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
	authzEngine = authzmw_otel.NewAuthzOTelMiddleware(authzEngine)

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

	var openApiContent []byte
	if conf.OpenAPI.Enabled {
		openApiContent = specs.Authz
	}

	port, err := routes.RunHttpRouter(lHttp, httpEngine, conf.Server, serviceInfo, openApiContent)
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

	if err := runConfiguredStorageMigrations(conf, lDB); err != nil {
		return nil, nil, nil, nil, err
	}

	policyStore, err := store.NewGormPolicyStore(authzDB)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to create policy store: %w", err)
	}

	principalManager, err := service.NewPrincipalManager(authzDB, conf.JWKSURL, conf.InsecureSkipJWTVerify)
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

	eng, err := engine.NewEngine(schemaDbs, conf.Schemas,
		engine.WithLogger(lEngine),
		engine.WithHTTPSchemas(conf.HTTPSchemas),
	)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	if err := seedStorage(context.Background(), conf, principalManager, policyManager); err != nil {
		return nil, nil, nil, nil, err
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

		if !service.IsSystemPolicy(policy.ID) {
			policy.ID = service.SystemPolicyPrefix + policy.ID
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
	Transport  postgresconfig.PostgresTransport `mapstructure:"transport"`
	Hostname   string                           `mapstructure:"hostname"`
	Port       int                              `mapstructure:"port"`
	Username   string                           `mapstructure:"username"`
	Password   cconfig.Password                 `mapstructure:"password"`
	Database   string                           `mapstructure:"database"`
	RDSDataAPI postgresconfig.RDSDataAPIConfig  `mapstructure:"rds_data_api"`
	// Schema sets the PostgreSQL search_path. Used when all services share one
	// database (e.g. monolithic mode where schemas live inside the "pki" DB).
	Schema string `mapstructure:"schema"`
}

func CreatePostgresDBConnection(log *logrus.Entry, cfg cconfig.PluggableStorageEngine) (*gorm.DB, error) {
	dbCfg, err := cconfig.DecodeStruct[postgresDBConfig](cfg.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to decode postgres config: %w", err)
	}

	if dbCfg.Transport == postgresconfig.PostgresTransportRDSDataAPI {
		dbCfg.Database = dbCfg.RDSDataAPI.Database
	}
	if dbCfg.Database == "" {
		return nil, fmt.Errorf("postgres config is missing required field 'database'")
	}

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=disable",
		dbCfg.Hostname, dbCfg.Username, string(dbCfg.Password), dbCfg.Database, dbCfg.Port)
	if dbCfg.Transport != postgresconfig.PostgresTransportRDSDataAPI && dbCfg.Schema != "" {
		dsn += " search_path=" + dbCfg.Schema
	}
	dialector, namingStrategy, err := postgresDialector(dbCfg, dsn)
	if err != nil {
		return nil, err
	}

	gormConfig := &gorm.Config{Logger: NewGormLogger(log)}
	if namingStrategy != nil {
		gormConfig.NamingStrategy = namingStrategy
	}
	db, err := gorm.Open(dialector, gormConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}

	if err := db.Use(authzgorm.NewAuthzGormPlugin()); err != nil {
		return nil, fmt.Errorf("failed to register authz gorm plugin: %w", err)
	}
	if dbCfg.Transport == postgresconfig.PostgresTransportRDSDataAPI {
		if err := db.Use(rdsgorm.NewTypeHintPlugin()); err != nil {
			return nil, fmt.Errorf("failed to register RDS Data API type hint plugin: %w", err)
		}
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)

	if dbCfg.Transport == postgresconfig.PostgresTransportRDSDataAPI {
		log.Infof("Connected to PostgreSQL database through the RDS Data API: %s", dbCfg.Database)
	} else {
		log.Infof("Connected to PostgreSQL database: %s@%s:%d/%s", dbCfg.Username, dbCfg.Hostname, dbCfg.Port, dbCfg.Database)
	}
	return db, nil
}

func postgresDialector(dbCfg postgresDBConfig, dsn string) (gorm.Dialector, schema.Namer, error) {
	switch dbCfg.Transport {
	case "", postgresconfig.PostgresTransportDirect:
		return gormpostgres.Open(dsn), nil, nil
	case postgresconfig.PostgresTransportRDSDataAPI:
		for _, required := range []struct {
			name  string
			value string
		}{
			{name: "resource_arn", value: dbCfg.RDSDataAPI.ResourceARN},
			{name: "secret_arn", value: dbCfg.RDSDataAPI.SecretARN},
			{name: "database", value: dbCfg.RDSDataAPI.Database},
			{name: "aws_region", value: dbCfg.RDSDataAPI.AWSRegion},
		} {
			if required.value == "" {
				return nil, nil, fmt.Errorf("RDS Data API authz connection requires %s", required.name)
			}
		}

		driverConfig := rds.NewConfig(
			dbCfg.RDSDataAPI.ResourceARN,
			dbCfg.RDSDataAPI.SecretARN,
			dbCfg.RDSDataAPI.Database,
			dbCfg.RDSDataAPI.AWSRegion,
		)
		driverConfig.ParseTime = true
		dialector := gormpostgres.New(gormpostgres.Config{
			DriverName: rds.DRIVERNAME,
			DSN:        driverConfig.ToDSN(),
		})
		var namingStrategy schema.Namer
		if dbCfg.Schema != "" {
			namingStrategy = storagepostgres.NewPostgresSchemaNamingStrategy(dbCfg.Schema)
		}
		return dialector, namingStrategy, nil
	default:
		return nil, nil, fmt.Errorf("unsupported PostgreSQL transport %q", dbCfg.Transport)
	}
}

func postgresMigrationConfig(conf authzconfig.AuthzConfig) (cconfig.PluggableStorageEngine, error) {
	if len(conf.MigrationDB.Config) > 0 {
		return conf.MigrationDB, nil
	}

	dbCfg, err := cconfig.DecodeStruct[postgresDBConfig](conf.AuthzDB.Config)
	if err != nil {
		return cconfig.PluggableStorageEngine{}, fmt.Errorf("failed to decode authz postgres config: %w", err)
	}
	if dbCfg.Transport == postgresconfig.PostgresTransportRDSDataAPI {
		return cconfig.PluggableStorageEngine{}, fmt.Errorf("Authz runtime uses the RDS Data API; configure migration_db with direct PostgreSQL connection settings for Goose migrations")
	}
	return conf.AuthzDB, nil
}

func CreatePostgresMigrationDBConnection(log *logrus.Entry, cfg cconfig.PluggableStorageEngine) (*gorm.DB, error) {
	dbCfg, err := cconfig.DecodeStruct[postgresDBConfig](cfg.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to decode postgres migration config: %w", err)
	}
	if dbCfg.Transport != "" && dbCfg.Transport != postgresconfig.PostgresTransportDirect {
		return nil, fmt.Errorf("PostgreSQL migrations require direct transport, got %q", dbCfg.Transport)
	}
	if dbCfg.Database == "" {
		return nil, fmt.Errorf("postgres migration config is missing required field 'database'")
	}

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=disable",
		dbCfg.Hostname, dbCfg.Username, string(dbCfg.Password), dbCfg.Database, dbCfg.Port)
	if dbCfg.Schema != "" {
		dsn += " search_path=" + dbCfg.Schema
	}
	db, err := gorm.Open(gormpostgres.Open(dsn), &gorm.Config{Logger: NewGormLogger(log)})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL for Authz migrations: %w", err)
	}
	return db, nil
}

func runConfiguredStorageMigrations(conf authzconfig.AuthzConfig, logger *logrus.Entry) error {
	sqlDB, err := openPostgresMigrationSQLDB(conf, logger)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := sqlDB.Close(); closeErr != nil {
			logger.WithError(closeErr).Error("failed to close Authz migration database connection")
		}
	}()
	return RunStorageMigrations(conf, sqlDB)
}

func openPostgresMigrationSQLDB(conf authzconfig.AuthzConfig, logger *logrus.Entry) (*sql.DB, error) {
	migrationConfig, err := postgresMigrationConfig(conf)
	if err != nil {
		return nil, err
	}
	migrationDB, err := CreatePostgresMigrationDBConnection(logger, migrationConfig)
	if err != nil {
		return nil, err
	}
	sqlDB, err := migrationDB.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get raw sql.DB for migrations: %w", err)
	}
	return sqlDB, nil
}
