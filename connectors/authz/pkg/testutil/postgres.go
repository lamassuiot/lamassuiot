package testutil

import (
	"fmt"
	"os"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
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
	Pool     *dockertest.Pool
	Resource *dockertest.Resource
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

	pool, err := dockertest.NewPool("")
	if err != nil {
		return nil, fmt.Errorf("could not construct pool: %w", err)
	}

	if err := pool.Client.Ping(); err != nil {
		return nil, fmt.Errorf("could not connect to Docker: %w", err)
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

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "postgres",
		Tag:        "15-alpine",
		Env: []string{
			fmt.Sprintf("POSTGRES_USER=%s", defaultUser),
			fmt.Sprintf("POSTGRES_PASSWORD=%s", defaultPassword),
			fmt.Sprintf("POSTGRES_DB=%s", defaultDBName),
		},
		Mounts: []string{
			fmt.Sprintf("%s:/docker-entrypoint-initdb.d/init.sql", initScriptPath),
		},
	}, func(config *docker.HostConfig) {
		config.AutoRemove = true
		config.RestartPolicy = docker.RestartPolicy{Name: "no"}
		// Let Docker assign a random available port to avoid conflicts
	})

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

	if err := pool.Retry(func() error {
		dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
			host, port, defaultUser, defaultPassword, defaultDBName)

		db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
			Logger: logger.Default.LogMode(logger.Info),
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
		return c.Pool.Purge(c.Resource)
	}
	return nil
}

func (c *PostgresContainer) DSN() string {
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		c.Host, c.Port, c.Username, c.Password, c.DBName)
}
