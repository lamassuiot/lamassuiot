package testutil

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	oraclestorage "github.com/lamassuiot/lamassuiot/v4/engines/storage/oracle"
	"github.com/lamassuiot/lamassuiot/v4/shared/subsystems/pkg/test/dockerrunner"
	"github.com/moby/moby/api/types/network"
	"github.com/ory/dockertest/v4"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	StorageProviderEnv = "LAMASSU_TEST_STORAGE_PROVIDER"
	defaultUser        = "postgres"
	defaultPassword    = "test"
	defaultDBName      = "authz_db"
	oracleUser         = "AUTHZ_TEST"
	oraclePassword     = "OracleTest_123"
	oracleImageTag     = "23.26.3-slim-faststart"
)

// DatabaseContainer is an isolated database used by Authz integration tests.
// PostgreSQL remains the default; set LAMASSU_TEST_STORAGE_PROVIDER=oracle to
// run these tests against Oracle.
type DatabaseContainer struct {
	DB      *gorm.DB
	cleanup func() error
}

func (c *DatabaseContainer) Cleanup() error {
	if c == nil || c.cleanup == nil {
		return nil
	}
	if c.DB != nil {
		if sqlDB, err := c.DB.DB(); err == nil {
			_ = sqlDB.Close()
		}
	}
	return c.cleanup()
}

func StorageProvider() string {
	provider := strings.ToLower(strings.TrimSpace(os.Getenv(StorageProviderEnv)))
	if provider == "" {
		return "postgres"
	}
	return provider
}

// RunWithMigration starts the selected database, loads the matching fixture,
// and returns a GORM connection. The Oracle fixture is the corresponding file
// with an .oracle.sql suffix.
func RunWithMigration(migrationPath string) (*DatabaseContainer, error) {
	provider := StorageProvider()
	switch provider {
	case "postgres", "postgresql":
		return runPostgresWithMigration(migrationPath)
	case "oracle":
		oraclePath := strings.TrimSuffix(migrationPath, ".sql") + ".oracle.sql"
		if _, err := os.Stat(oraclePath); err != nil {
			return nil, fmt.Errorf("Oracle test fixture %q is required: %w", oraclePath, err)
		}
		return runOracleWithMigration(oraclePath)
	default:
		return nil, fmt.Errorf("unsupported Authz test storage provider %q (supported: postgres, oracle)", provider)
	}
}

// RunEmpty starts an empty database for tests that apply Authz migrations.
func RunEmpty() (*DatabaseContainer, error) {
	switch StorageProvider() {
	case "postgres", "postgresql":
		return runPostgresWithMigration("")
	case "oracle":
		return runOracleWithMigration("")
	default:
		return nil, fmt.Errorf("unsupported Authz test storage provider %q (supported: postgres, oracle)", StorageProvider())
	}
}

func runPostgresWithMigration(migrationPath string) (*DatabaseContainer, error) {
	options := []dockertest.RunOption{
		dockertest.WithTag("15-alpine"),
		dockertest.WithEnv([]string{
			fmt.Sprintf("POSTGRES_USER=%s", defaultUser),
			fmt.Sprintf("POSTGRES_PASSWORD=%s", defaultPassword),
			fmt.Sprintf("POSTGRES_DB=%s", defaultDBName),
		}),
	}
	if migrationPath != "" {
		migrationContent, err := os.ReadFile(migrationPath)
		if err != nil {
			return nil, fmt.Errorf("read PostgreSQL test fixture: %w", err)
		}
		pwd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("get working directory: %w", err)
		}
		testdataDir := filepath.Join(pwd, "testdata")
		if err := os.MkdirAll(testdataDir, 0755); err != nil {
			return nil, fmt.Errorf("create testdata directory: %w", err)
		}
		initScriptPath := filepath.Join(testdataDir, "init.sql")
		if err := os.WriteFile(initScriptPath, migrationContent, 0644); err != nil {
			return nil, fmt.Errorf("write PostgreSQL init script: %w", err)
		}
		options = append(options, dockertest.WithMounts([]string{
			fmt.Sprintf("%s:/docker-entrypoint-initdb.d/init.sql", initScriptPath),
		}))
	}

	cleanup, resource, pool, err := dockerrunner.RunDocker("postgres", options...)
	if err != nil {
		return nil, fmt.Errorf("start PostgreSQL test database: %w", err)
	}
	container := &DatabaseContainer{cleanup: cleanup}
	port := resource.GetPort("5432/tcp")
	if err := pool.Retry(context.Background(), 0, func() error {
		dsn := fmt.Sprintf("host=localhost port=%s user=%s password=%s dbname=%s sslmode=disable",
			port, defaultUser, defaultPassword, defaultDBName)
		db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
		if err != nil {
			return err
		}
		sqlDB, err := db.DB()
		if err != nil {
			return err
		}
		if err := sqlDB.Ping(); err != nil {
			return err
		}
		container.DB = db
		return nil
	}); err != nil {
		_ = container.Cleanup()
		return nil, fmt.Errorf("connect to PostgreSQL test database: %w", err)
	}
	return container, nil
}

func runOracleWithMigration(migrationPath string) (*DatabaseContainer, error) {
	cleanup, resource, pool, err := dockerrunner.RunDocker("gvenzl/oracle-free",
		dockertest.WithTag(oracleImageTag),
		dockertest.WithEnv([]string{
			"ORACLE_PASSWORD=" + oraclePassword,
			"APP_USER=" + oracleUser,
			"APP_USER_PASSWORD=" + oraclePassword,
		}),
		dockertest.WithLabels(map[string]string{"group": "lamassuiot-tests", "engine": "oracle", "service": "authz"}),
		dockertest.WithPortBindings(network.PortMap{
			network.MustParsePort("1521/tcp"): []network.PortBinding{{
				HostIP: netip.MustParseAddr("0.0.0.0"),
			}},
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("start Oracle Authz test database: %w", err)
	}
	container := &DatabaseContainer{cleanup: cleanup}
	connectString := fmt.Sprintf("localhost:%s/FREEPDB1", resource.GetPort("1521/tcp"))
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	err = pool.Retry(ctx, 3*time.Minute, func() error {
		pool, err := oraclestorage.OpenDatabaseWithOptions(ctx, oraclestorage.ConnectionOptions{
			ConnectString: connectString,
			Username:      oracleUser,
			Password:      oraclePassword,
			MaxOpenConns:  8,
		})
		if err != nil {
			return err
		}
		db, err := oraclestorage.OpenGORM(pool)
		if err != nil {
			_ = pool.Close()
			return err
		}
		db.Logger = logger.Default.LogMode(logger.Silent)
		container.DB = db
		return nil
	})
	if err != nil {
		_ = container.Cleanup()
		return nil, fmt.Errorf("connect to Oracle Authz test database: %w", err)
	}
	if migrationPath != "" {
		content, err := os.ReadFile(migrationPath)
		if err != nil {
			_ = container.Cleanup()
			return nil, fmt.Errorf("read Oracle test fixture: %w", err)
		}
		for _, statement := range strings.Split(string(content), ";") {
			statement = strings.TrimSpace(statement)
			if statement == "" {
				continue
			}
			if err := container.DB.Exec(statement).Error; err != nil {
				_ = container.Cleanup()
				return nil, fmt.Errorf("apply Oracle test fixture statement %q: %w", statement, err)
			}
		}
	}
	return container, nil
}
