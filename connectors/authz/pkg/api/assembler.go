package api

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/lamassuiot/authz/pkg/authz"
	authzmodels "github.com/lamassuiot/authz/pkg/models"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
	"gocloud.dev/blob"
	_ "gocloud.dev/blob/fileblob"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

type Config struct {
	Debug       bool
	Port        int
	Schemas     map[string]string
	Credentials map[string]CredentialConfig
	PreloadDir  string
}

type CredentialConfig struct {
	Username string
	Password string
	Host     string
	Port     int
	Database string
}

func AssembleAuthzServiceWithHTTPServer(cfg Config) (int, error) {
	principalManager, engine, policyManager, err := AssembleAuthzService(cfg)
	if err != nil {
		return -1, fmt.Errorf("failed to assemble Authz service: %w", err)
	}

	lHttp := helpers.SetupLogger(config.Debug, "AUTHZ", "HTTP Server")
	httpEngine := routes.NewGinEngine(lHttp)
	httpGrp := httpEngine.Group("/")

	NewAuthzRoutes(httpGrp, principalManager, engine, policyManager, lHttp)

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

func AssembleAuthzService(cfg Config) (*authz.PrincipalManager, *authz.Engine, *authz.PolicyManager, error) {
	lDB := helpers.SetupLogger(config.Trace, "AUTHZ", "DB")
	lBucketStore := helpers.SetupLogger(config.Debug, "AUTHZ", "BucketStore")

	// Create SQLite DB for principal management
	principalDB, err := CreateSQLiteDBConnection(lDB, "authz_principals.db", "")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create principal database: %w", err)
	}

	// Create policy store
	policyStore, err := CreateBucketStore(lBucketStore, "policy_store")
	if err != nil {
		return nil, nil, nil, err
	}

	// Create principal manager
	principalManager, err := authz.NewPrincipalManager(principalDB, policyStore)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create database connections for each schema
	schemaDbs := make(map[string]*gorm.DB)
	for schemaName, credentials := range cfg.Credentials {
		lDB.Infof("Creating database connection for schema: %s", schemaName)
		db, err := CreatePostgresDBConnection(lDB, credentials)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to create database connection for schema %s: %w", schemaName, err)
		}
		schemaDbs[schemaName] = db
	}

	// Create engine with multiple database connections
	engine, err := authz.NewEngine(schemaDbs, cfg.Schemas)
	if err != nil {
		return nil, nil, nil, err
	}

	policyManager := authz.NewPolicyManager(policyStore)

	if cfg.PreloadDir != "" {
		lPreload := helpers.SetupLogger(config.Debug, "AUTHZ", "Preload")
		if err := preloadPolicies(context.Background(), policyManager, cfg.PreloadDir, lPreload); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to preload policies: %w", err)
		}
	}

	return principalManager, engine, policyManager, nil
}

// preloadPolicies reads all JSON files from dir and creates them as policies if they don't already exist.
func preloadPolicies(ctx context.Context, pm *authz.PolicyManager, dir string, log *logrus.Entry) error {
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

func CreateBucketStore(log *logrus.Entry, dbPath string) (*blob.Bucket, error) {
	os.MkdirAll(dbPath, 0755)

	uri := fmt.Sprintf("file://%s?no_tmp_dir", dbPath)
	bucket, err := blob.OpenBucket(context.Background(), uri)
	if err != nil {
		return nil, err
	}

	return bucket, nil
}

func CreateSQLiteDBConnection(log *logrus.Entry, dbPath string, migrationPath string) (*gorm.DB, error) {
	dbLogger := &GormLogger{
		Logger: log,
	}

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: dbLogger,
	})
	if err != nil {
		return nil, err
	}

	// Get underlying SQL DB for connection pool configuration
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	// Configure connection pool for concurrency protection
	// SQLite performs best with a single writer, so limit max open connections
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(time.Hour)

	// Enable WAL mode for better concurrent read/write performance
	if err := db.Exec("PRAGMA journal_mode = WAL").Error; err != nil {
		return nil, err
	}

	// Enable Foreign Keys
	if err := db.Exec("PRAGMA foreign_keys = ON").Error; err != nil {
		return nil, err
	}

	// Set busy timeout to wait up to 5 seconds for locks
	if err := db.Exec("PRAGMA busy_timeout = 5000").Error; err != nil {
		return nil, err
	}

	// Set synchronous mode to NORMAL for better performance while maintaining safety
	if err := db.Exec("PRAGMA synchronous = NORMAL").Error; err != nil {
		return nil, err
	}

	// Disable case-sensitive LIKE to match PostgreSQL ILIKE behavior
	if err := db.Exec("PRAGMA case_sensitive_like = OFF").Error; err != nil {
		return nil, err
	}

	// Run migrations if migration file is provided
	if migrationPath != "" {
		if err := runMigrations(db, migrationPath, log); err != nil {
			log.Warnf("Failed to run migrations: %v", err)
			// Don't fail if migrations already ran - tables might exist
		}
	}

	return db, nil
}

func CreatePostgresDBConnection(log *logrus.Entry, cfg CredentialConfig) (*gorm.DB, error) {
	dbLogger := &GormLogger{
		Logger: log,
	}

	// Build PostgreSQL connection string
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=disable",
		cfg.Host, cfg.Username, cfg.Password, cfg.Database, cfg.Port)

	// Import postgres driver
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: dbLogger,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}

	// Get underlying SQL DB for connection pool configuration
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	// Configure connection pool
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)

	log.Infof("Connected to PostgreSQL database: %s@%s:%d/%s", cfg.Username, cfg.Host, cfg.Port, cfg.Database)
	return db, nil
}

// runMigrations executes SQL migration file
func runMigrations(db *gorm.DB, migrationPath string, log *logrus.Entry) error {
	// Check if migration file exists
	if _, err := os.Stat(migrationPath); os.IsNotExist(err) {
		log.Warnf("Migration file not found: %s", migrationPath)
		return nil // Don't fail if file doesn't exist
	}

	// Read migration file
	sqlContent, err := os.ReadFile(migrationPath)
	if err != nil {
		return fmt.Errorf("failed to read migration file: %w", err)
	}

	// Execute migration SQL
	if err := db.Exec(string(sqlContent)).Error; err != nil {
		// Log but don't fail on errors (tables might already exist)
		log.Debugf("Migration execution result: %v", err)
		return err
	}

	log.Infof("Successfully executed migrations from %s", migrationPath)
	return nil
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
