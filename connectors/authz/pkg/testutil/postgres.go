package testutil

import (
	"context"
	"fmt"
	"os"

	"github.com/lamassuiot/lamassuiot/v4/shared/subsystems/pkg/test/dockerrunner"
	"github.com/ory/dockertest/v4"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	defaultUser     = "postgres"
	defaultPassword = "test"
	defaultDBName   = "authz_db"
)

type PostgresContainer struct {
	Pool     dockertest.ClosablePool
	Resource dockertest.ClosableResource
	DB       *gorm.DB
	Host     string
	Port     string
	DBName   string
	Username string
	Password string
}

func RunPostgresWithMigration(migrationPath string) (*PostgresContainer, error) {
	migrationContent, err := os.ReadFile(migrationPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read migration file: %w", err)
	}

	pwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get working directory: %w", err)
	}

	testdataDir := fmt.Sprintf("%s/testdata", pwd)
	os.MkdirAll(testdataDir, 0755)

	initScriptPath := fmt.Sprintf("%s/init.sql", testdataDir)
	if err := os.WriteFile(initScriptPath, migrationContent, 0644); err != nil {
		return nil, fmt.Errorf("failed to write init script: %w", err)
	}

	_, resource, pool, err := dockerrunner.RunDocker("postgres",
		dockertest.WithTag("15-alpine"),
		dockertest.WithEnv([]string{
			fmt.Sprintf("POSTGRES_USER=%s", defaultUser),
			fmt.Sprintf("POSTGRES_PASSWORD=%s", defaultPassword),
			fmt.Sprintf("POSTGRES_DB=%s", defaultDBName),
		}),
		dockertest.WithMounts([]string{
			fmt.Sprintf("%s:/docker-entrypoint-initdb.d/init.sql", initScriptPath),
		}),
	)

	if err != nil {
		return nil, fmt.Errorf("could not start resource: %w", err)
	}

	port := resource.GetPort("5432/tcp")
	host := "localhost"

	container := &PostgresContainer{
		Pool:     pool,
		Resource: resource,
		Host:     host,
		Port:     port,
		DBName:   defaultDBName,
		Username: defaultUser,
		Password: defaultPassword,
	}

	if err := pool.Retry(context.Background(), 0, func() error {
		dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
			host, port, defaultUser, defaultPassword, defaultDBName)

		db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
			Logger: logger.Default.LogMode(logger.Silent),
		})
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
		container.Cleanup()
		return nil, fmt.Errorf("could not connect to database: %w", err)
	}

	fmt.Printf("PostgreSQL container started on port %s\n", port)
	return container, nil
}

func (c *PostgresContainer) Cleanup() error {
	if c.Resource != nil {
		return c.Pool.Close(context.Background())
	}
	return nil
}

func (c *PostgresContainer) DSN() string {
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		c.Host, c.Port, c.Username, c.Password, c.DBName)
}

// RunPostgresEmpty starts a Postgres 15-alpine container with no init SQL.
// The caller is responsible for running any schema migrations after connecting.
func RunPostgresEmpty() (*PostgresContainer, error) {
	_, resource, pool, err := dockerrunner.RunDocker("postgres",
		dockertest.WithTag("15-alpine"),
		dockertest.WithEnv([]string{
			fmt.Sprintf("POSTGRES_USER=%s", defaultUser),
			fmt.Sprintf("POSTGRES_PASSWORD=%s", defaultPassword),
			fmt.Sprintf("POSTGRES_DB=%s", defaultDBName),
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("could not start resource: %w", err)
	}

	port := resource.GetPort("5432/tcp")
	host := "localhost"

	container := &PostgresContainer{
		Pool:     pool,
		Resource: resource,
		Host:     host,
		Port:     port,
		DBName:   defaultDBName,
		Username: defaultUser,
		Password: defaultPassword,
	}

	if err := pool.Retry(context.Background(), 0, func() error {
		dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
			host, port, defaultUser, defaultPassword, defaultDBName)

		db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
			Logger: logger.Default.LogMode(logger.Silent),
		})
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
		container.Cleanup()
		return nil, fmt.Errorf("could not connect to database: %w", err)
	}

	fmt.Printf("PostgreSQL container started on port %s\n", port)
	return container, nil
}
