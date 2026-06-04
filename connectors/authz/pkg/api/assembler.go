package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/lamassuiot/authz/pkg/engine"
	authzmodels "github.com/lamassuiot/authz/pkg/models"
	"github.com/lamassuiot/authz/pkg/service"
	"github.com/lamassuiot/authz/pkg/store"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

type Config struct {
	Debug       bool
	Port        int
	LogFile     string
	Schemas     map[string]string
	Credentials map[string]config.PluggableStorageEngine
	PreloadDir  string
	// AuthzDB holds connection details for the authz service's own Postgres database
	// (principals, grants, policies).  It is distinct from the per-schema engine DBs.
	AuthzDB config.PluggableStorageEngine
}

// openLogFile returns an io.Writer that tees to the named file alongside the
// existing logger output.  Returns nil when logFile is empty (no-op).
func openLogFile(logFile string) (io.Writer, error) {
	if logFile == "" {
		return nil, nil
	}
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file %q: %w", logFile, err)
	}
	return f, nil
}

// addFileOutput wraps the logger's current output with an io.MultiWriter so
// entries are written to both the existing destination and the file.
// Does nothing when fileWriter is nil.
func addFileOutput(entry *logrus.Entry, fileWriter io.Writer) {
	if fileWriter == nil {
		return
	}
	entry.Logger.SetOutput(io.MultiWriter(entry.Logger.Out, fileWriter))
	entry.Logger.SetFormatter(&OrderedJSONFormatter{FieldOrder: authzFieldOrder})
}

func AssembleAuthzServiceWithHTTPServer(cfg Config) (int, error) {
	fileWriter, err := openLogFile(cfg.LogFile)
	if err != nil {
		return -1, err
	}

	principalManager, eng, policyManager, resolver, err := AssembleAuthzService(cfg, fileWriter)
	if err != nil {
		return -1, fmt.Errorf("failed to assemble Authz service: %w", err)
	}

	lHttp := helpers.SetupLogger(config.Debug, "AUTHZ", "HTTP Server")
	addFileOutput(lHttp, fileWriter)

	httpEngine := routes.NewGinEngine(lHttp)
	httpGrp := httpEngine.Group("/")

	NewAuthzRoutes(httpGrp, principalManager, eng, policyManager, resolver, lHttp)

	port, err := routes.RunHttpRouter(
		lHttp,
		httpEngine,
		config.HttpServer{
			LogLevel:      config.Debug,
			ListenAddress: "0.0.0.0",
			Port:          cfg.Port,
			Protocol:      config.HTTP,
		},
		models.APIServiceInfo{Version: "", BuildSHA: "", BuildTime: ""},
	)
	if err != nil {
		return -1, fmt.Errorf("failed to start Authz HTTP server: %w", err)
	}

	lHttp.Infof("Authz Service is running on port %d", port)
	return port, nil
}

func AssembleAuthzService(cfg Config, fileWriter io.Writer) (*service.PrincipalManager, *engine.Engine, *service.PolicyManager, *service.IdentityResolver, error) {
	lDB := helpers.SetupLogger(config.Trace, "AUTHZ", "DB")
	addFileOutput(lDB, fileWriter)

	// Connect to the authz Postgres database (principals, grants, policies).
	authzDB, err := CreatePostgresDBConnection(lDB, cfg.AuthzDB)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to connect to authz database: %w", err)
	}

	// Build policy store backed by Postgres.
	policyStore, err := store.NewGormPolicyStore(authzDB)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to create policy store: %w", err)
	}

	// Build principal manager (also runs AutoMigrate for principals/grants tables).
	principalManager, err := service.NewPrincipalManager(authzDB)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	policyManager := service.NewPolicyManager(policyStore)

	// Connect to per-schema engine databases.
	schemaDbs := make(map[string]*gorm.DB)
	for schemaName, credentials := range cfg.Credentials {
		lDB.Infof("Creating database connection for schema: %s", schemaName)
		db, err := CreatePostgresDBConnection(lDB, credentials)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to create database connection for schema %s: %w", schemaName, err)
		}
		schemaDbs[schemaName] = db
	}

	lEngine := helpers.SetupLogger(config.Debug, "AUTHZ", "Engine")
	addFileOutput(lEngine, fileWriter)

	eng, err := engine.NewEngine(schemaDbs, cfg.Schemas, engine.WithLogger(lEngine))
	if err != nil {
		return nil, nil, nil, nil, err
	}

	if cfg.PreloadDir != "" {
		lPreload := helpers.SetupLogger(config.Debug, "AUTHZ", "Preload")
		addFileOutput(lPreload, fileWriter)
		if err := preloadPolicies(context.Background(), policyManager, cfg.PreloadDir, lPreload); err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to preload policies: %w", err)
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

		if err := pm.CreatePolicy(ctx, &policy); err != nil {
			log.Warnf("Skipping preload file %s: %v", filePath, err)
			continue
		}

		log.Infof("Preloaded policy %q (id=%s) from %s", policy.Name, policy.ID, filePath)
	}

	return nil
}

func CreatePostgresDBConnection(log *logrus.Entry, cfg config.PluggableStorageEngine) (*gorm.DB, error) {
	dbLogger := &GormLogger{
		Logger: log,
	}

	host, _ := cfg.Config["hostname"].(string)
	port, _ := cfg.Config["port"].(int)
	username, _ := cfg.Config["username"].(string)
	password := string(cfg.Config["password"].(config.Password))
	database := "authz"

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=disable",
		host, username, password, database, port)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: dbLogger,
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

	log.Infof("Connected to PostgreSQL database: %s@%s:%d/%s", username, host, port, database)
	return db, nil
}

func NewGormLogger(logger *logrus.Entry) *GormLogger {
	return &GormLogger{
		Logger: logger,
	}
}

// Logrus GORM iface implementation
// https://www.soberkoder.com/go-gorm-logging/
type GormLogger struct {
	Logger *logrus.Entry
}

func (l *GormLogger) LogMode(lvl gormlogger.LogLevel) gormlogger.Interface {
	newlogger := *l
	return &newlogger
}

func (l *GormLogger) Info(ctx context.Context, str string, rest ...interface{}) {
	le := helpers.ConfigureLogger(ctx, l.Logger)
	le.Infof(str, rest...)
}

func (l *GormLogger) Warn(ctx context.Context, str string, rest ...interface{}) {
	le := helpers.ConfigureLogger(ctx, l.Logger)
	le.Warnf(str, rest...)
}

func (l *GormLogger) Error(ctx context.Context, str string, rest ...interface{}) {
	le := helpers.ConfigureLogger(ctx, l.Logger)
	le.Errorf(str, rest...)
}

func (l *GormLogger) Trace(ctx context.Context, begin time.Time, fc func() (sql string, rowsAffected int64), err error) {
	le := helpers.ConfigureLogger(ctx, l.Logger)
	sql, rows := fc()
	if err != nil {
		le.Errorf("Took: %s, Err:%s, SQL: %s, AffectedRows: %d", time.Since(begin).String(), err, sql, rows)
	} else {
		le.Tracef("Took: %s, SQL: %s, AffectedRows: %d", time.Since(begin).String(), sql, rows)
	}
}
