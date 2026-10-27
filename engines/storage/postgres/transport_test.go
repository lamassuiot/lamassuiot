package postgres

import (
	"testing"

	rds "github.com/krotscheck/go-rds-driver"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	lconfig "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/config"
	"github.com/stretchr/testify/require"
	pgdialector "gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type schemaQualifiedTestModel struct {
	ID string
}

func TestPostgresDialectorDefaultsToDirectTransport(t *testing.T) {
	dialector, err := postgresDialector(lconfig.PostgresPSEConfig{}, "direct postgres DSN")
	require.NoError(t, err)

	postgresDialector, ok := dialector.(*pgdialector.Dialector)
	require.True(t, ok)
	require.Empty(t, postgresDialector.Config.DriverName)
	require.Equal(t, "direct postgres DSN", postgresDialector.Config.DSN)
}

func TestPostgresDialectorConfiguresRDSDataAPITransport(t *testing.T) {
	input := map[string]any{
		"transport": "rds_data_api",
		"rds_data_api": map[string]any{
			"resource_arn": "resource-arn",
			"secret_arn":   "secret-arn",
			"database":     "pki",
			"aws_region":   "us-east-1",
		},
	}
	cfg, err := config.DecodeStruct[lconfig.PostgresPSEConfig](input)
	require.NoError(t, err)

	dialector, err := postgresDialector(cfg, "unused direct DSN")
	require.NoError(t, err)
	postgresDialector, ok := dialector.(*pgdialector.Dialector)
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

func TestPostgresDialectorRejectsInvalidRDSDataAPIConfig(t *testing.T) {
	_, err := postgresDialector(lconfig.PostgresPSEConfig{
		Transport: lconfig.PostgresTransportRDSDataAPI,
	}, "unused direct DSN")
	require.ErrorContains(t, err, "requires resource_arn")

	_, err = postgresDialector(lconfig.PostgresPSEConfig{
		Transport: "unsupported",
	}, "unused direct DSN")
	require.ErrorContains(t, err, "unsupported PostgreSQL transport")
}

func TestTypeHintPluginIsEnabledOnlyForRDSDataAPI(t *testing.T) {
	for _, testCase := range []struct {
		name               string
		transport          lconfig.PostgresTransport
		wantTypeHintPlugin bool
	}{
		{
			name:               "direct transport",
			transport:          lconfig.PostgresTransportDirect,
			wantTypeHintPlugin: false,
		},
		{
			name:               "RDS Data API transport",
			transport:          lconfig.PostgresTransportRDSDataAPI,
			wantTypeHintPlugin: true,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			db, err := gorm.Open(pgdialector.Open(""), &gorm.Config{DisableAutomaticPing: true})
			require.NoError(t, err)
			sqlDB, err := db.DB()
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, sqlDB.Close()) })

			require.NoError(t, configurePostgresGORMPlugins(db, testCase.transport))
			_, gotTypeHintPlugin := db.Config.Plugins["rds:type_hints"]
			require.Equal(t, testCase.wantTypeHintPlugin, gotTypeHintPlugin)
		})
	}
}

func TestRDSDataAPISchemaQualification(t *testing.T) {
	db, err := gorm.Open(pgdialector.Open(""), &gorm.Config{
		DisableAutomaticPing: true,
		DryRun:               true,
		NamingStrategy:       newPostgresSchemaNamingStrategy("ca"),
	})
	require.NoError(t, err)

	var rows []schemaQualifiedTestModel
	querier := &DBQuerier[schemaQualifiedTestModel]{
		DB:        db,
		tableName: "ca_certificates",
	}

	explicitTableQuery := querier.Table(querier.tableName).Find(&rows)
	require.NoError(t, explicitTableQuery.Error)
	require.Equal(t, `SELECT * FROM "ca"."ca_certificates"`, explicitTableQuery.Statement.SQL.String())

	modelTableQuery := db.Model(&schemaQualifiedTestModel{}).Find(&rows)
	require.NoError(t, modelTableQuery.Error)
	require.Equal(t, `SELECT * FROM "ca"."schema_qualified_test_models"`, modelTableQuery.Statement.SQL.String())

	require.Equal(t,
		"JOIN ca.certificates ON ca_certificates.serial_number = certificates.serial_number",
		caJoinCaCertificatesAndCertificates(db),
	)
	require.Equal(t, "ca.device_groups", qualifiedTableName(db, "device_groups"))
}

func TestDirectTransportDoesNotQualifyExplicitTableNames(t *testing.T) {
	db, err := gorm.Open(pgdialector.Open(""), &gorm.Config{
		DisableAutomaticPing: true,
		DryRun:               true,
	})
	require.NoError(t, err)

	var rows []schemaQualifiedTestModel
	querier := &DBQuerier[schemaQualifiedTestModel]{
		DB:        db,
		tableName: "ca_certificates",
	}

	query := querier.Table(querier.tableName).Find(&rows)
	require.NoError(t, query.Error)
	require.Equal(t, `SELECT * FROM "ca_certificates"`, query.Statement.SQL.String())
	require.Equal(t,
		"JOIN certificates ON ca_certificates.serial_number = certificates.serial_number",
		caJoinCaCertificatesAndCertificates(db),
	)
}
