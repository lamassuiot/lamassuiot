package api

import (
	"context"
	"database/sql"
	"fmt"

	authzconfig "github.com/lamassuiot/authz/pkg/config"
	"github.com/lamassuiot/authz/pkg/service"
	"github.com/lamassuiot/authz/pkg/store"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
)

// InitializeStorage applies migrations, preloads policies and seeds bootstrap
// principals, then returns. It backs the `init` command, which prepares the
// database before the service is deployed. AssembleAuthzService performs the
// same steps at startup, so monolithic and development modes keep working
// without a separate init step.
func InitializeStorage(ctx context.Context, conf authzconfig.AuthzConfig) error {
	lDB := helpers.SetupLogger(conf.Logs.Level, "AUTHZ", "DB")

	authzDB, err := CreatePostgresDBConnection(lDB, conf.AuthzDB)
	if err != nil {
		return fmt.Errorf("failed to connect to authz database: %w", err)
	}

	sqlDB, err := authzDB.DB()
	if err != nil {
		return fmt.Errorf("failed to get raw sql.DB: %w", err)
	}
	defer sqlDB.Close()

	if err := RunStorageMigrations(conf, sqlDB); err != nil {
		return err
	}

	policyStore, err := store.NewGormPolicyStore(authzDB)
	if err != nil {
		return fmt.Errorf("failed to create policy store: %w", err)
	}

	principalManager, err := service.NewPrincipalManager(authzDB, conf.JWKSURL, conf.EnableJWTValidation)
	if err != nil {
		return err
	}

	return seedStorage(ctx, conf, principalManager, service.NewPolicyManager(policyStore))
}

// RunMigrateCommand runs a single goose command against the authz database and
// returns. It backs the `migrate` command.
func RunMigrateCommand(ctx context.Context, conf authzconfig.AuthzConfig, command string, args []string) error {
	lDB := helpers.SetupLogger(conf.Logs.Level, "AUTHZ", "DB")

	authzDB, err := CreatePostgresDBConnection(lDB, conf.AuthzDB)
	if err != nil {
		return fmt.Errorf("failed to connect to authz database: %w", err)
	}

	sqlDB, err := authzDB.DB()
	if err != nil {
		return fmt.Errorf("failed to get raw sql.DB: %w", err)
	}
	defer sqlDB.Close()

	schema, err := authzDBSchema(conf)
	if err != nil {
		return err
	}

	lMigrate := helpers.SetupLogger(conf.Logs.Level, "AUTHZ", "Migrate")
	return store.RunMigrationCommand(ctx, sqlDB, schema, command, args, lMigrate)
}

// RunStorageMigrations applies all pending migrations to the authz database.
func RunStorageMigrations(conf authzconfig.AuthzConfig, sqlDB *sql.DB) error {
	schema, err := authzDBSchema(conf)
	if err != nil {
		return err
	}

	lMigrate := helpers.SetupLogger(conf.Logs.Level, "AUTHZ", "Migrate")
	if err := store.RunMigrations(sqlDB, schema, lMigrate); err != nil {
		return fmt.Errorf("database migration failed: %w", err)
	}
	return nil
}

// seedStorage preloads policies and then applies bootstrap entries. Order
// matters: grants declared in bootstrap reference policies that preload creates.
func seedStorage(ctx context.Context, conf authzconfig.AuthzConfig, principalManager *service.PrincipalManager, policyManager *service.PolicyManager) error {
	if conf.PreloadDir != "" {
		lPreload := helpers.SetupLogger(conf.Logs.Level, "AUTHZ", "Preload")
		if err := preloadPolicies(ctx, policyManager, conf.PreloadDir, lPreload); err != nil {
			return fmt.Errorf("failed to preload policies: %w", err)
		}
	}

	if len(conf.Bootstrap) > 0 {
		lBootstrap := helpers.SetupLogger(conf.Logs.Level, "AUTHZ", "Bootstrap")
		if err := runBootstrap(ctx, principalManager, conf.Bootstrap, lBootstrap); err != nil {
			return fmt.Errorf("failed to run bootstrap: %w", err)
		}
	}

	return nil
}

func authzDBSchema(conf authzconfig.AuthzConfig) (string, error) {
	dbCfg, err := cconfig.DecodeStruct[postgresDBConfig](conf.AuthzDB.Config)
	if err != nil {
		return "", fmt.Errorf("failed to decode authz postgres config: %w", err)
	}
	return dbCfg.Schema, nil
}
