package api

import (
	"testing"

	rds "github.com/krotscheck/go-rds-driver"
	authzconfig "github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/config"
	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	postgresconfig "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/config"
	"github.com/stretchr/testify/require"
	gormpostgres "gorm.io/driver/postgres"
)

func TestPostgresDialectorConfiguresRDSDataAPI(t *testing.T) {
	dbCfg := postgresDBConfig{
		Transport: postgresconfig.PostgresTransportRDSDataAPI,
		Schema:    "authz",
		RDSDataAPI: postgresconfig.RDSDataAPIConfig{
			ResourceARN: "resource-arn",
			SecretARN:   "secret-arn",
			Database:    "pki",
			AWSRegion:   "us-east-1",
		},
	}

	dialector, namingStrategy, err := postgresDialector(dbCfg, "unused")
	require.NoError(t, err)
	require.NotNil(t, namingStrategy)

	postgresDialector, ok := dialector.(*gormpostgres.Dialector)
	require.True(t, ok)
	require.Equal(t, rds.DRIVERNAME, postgresDialector.Config.DriverName)

	driverConfig, err := rds.NewConfigFromDSN(postgresDialector.Config.DSN)
	require.NoError(t, err)
	require.Equal(t, "resource-arn", driverConfig.ResourceArn)
	require.Equal(t, "secret-arn", driverConfig.SecretArn)
	require.Equal(t, "pki", driverConfig.Database)
	require.Equal(t, "us-east-1", driverConfig.AWSRegion)
	require.True(t, driverConfig.ParseTime)
}

func TestPostgresMigrationConfigRequiresDirectConfigForDataAPI(t *testing.T) {
	conf := authzconfig.AuthzConfig{
		AuthzDB: cconfig.PluggableStorageEngine{
			Config: map[string]any{
				"transport": "rds_data_api",
				"rds_data_api": map[string]any{
					"resource_arn": "resource-arn",
					"secret_arn":   "secret-arn",
					"database":     "pki",
					"aws_region":   "us-east-1",
				},
			},
		},
	}

	_, err := postgresMigrationConfig(conf)
	require.ErrorContains(t, err, "configure migration_db")

	conf.MigrationDB = cconfig.PluggableStorageEngine{
		Config: map[string]any{"database": "pki"},
	}
	migrationConfig, err := postgresMigrationConfig(conf)
	require.NoError(t, err)
	require.Equal(t, "pki", migrationConfig.Config["database"])
}

func TestPostgresMigrationConfigFallsBackToDirectAuthzDB(t *testing.T) {
	authzDB := cconfig.PluggableStorageEngine{
		Config: map[string]any{
			"database": "pki",
			"hostname": "postgres.example.com",
			"port":     5432,
		},
	}
	migrationConfig, err := postgresMigrationConfig(authzconfig.AuthzConfig{AuthzDB: authzDB})
	require.NoError(t, err)
	require.Equal(t, authzDB, migrationConfig)
}
