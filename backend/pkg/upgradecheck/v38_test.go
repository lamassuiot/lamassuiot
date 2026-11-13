package upgradecheck

import (
	"context"
	"testing"

	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	lconfig "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/config"
	postgres_test "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/test"
	"github.com/stretchr/testify/require"
)

// v38Versions are the last migrations of each schema at tag backend/v3.8.1, in migration order.
var v38Versions = []struct {
	schema  string
	version int64
}{
	{postgres.KMS_SCHEMA, 20251031174938},
	{postgres.CA_SCHEMA, 20260520120000},
	{postgres.VA_SCHEMA, 1},
}

var testLogger = helpers.SetupLogger(cconfig.Info, "test", "upgrade-check")

// runV38DB starts a Postgres whose ca, kms and va schemas are at their 3.8.1 versions.
func runV38DB(t *testing.T) *lconfig.PostgresPSEConfig {
	t.Helper()
	schemas := map[string]string{}
	for _, v := range v38Versions {
		schemas[v.schema] = ""
	}
	cleanup, cfg, err := postgres_test.RunPostgresDocker(schemas, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = cleanup() })

	for _, v := range v38Versions {
		db, err := postgres.CreatePostgresDBConnection(testLogger, *cfg, v.schema)
		require.NoError(t, err)
		_, err = postgres.NewMigrator(testLogger, db).Goose.UpTo(context.Background(), v.version)
		require.NoError(t, err, "migrate %s to %d", v.schema, v.version)
	}
	return cfg
}

// migrateV4 applies every v4 migration in the order of the services, as postgres.MigrateAllSchemas does, but
// returns the error of a failing migration: the migrator of the services stops the process instead.
func migrateV4(t *testing.T, cfg *lconfig.PostgresPSEConfig) error {
	t.Helper()
	for _, schema := range postgres.MigrationSchemaOrder() {
		db, err := postgres.CreatePostgresDBConnection(testLogger, *cfg, schema)
		require.NoError(t, err)
		require.NoError(t, db.Exec("CREATE SCHEMA IF NOT EXISTS "+schema).Error)
		if _, err := postgres.NewMigrator(testLogger, db).Goose.Up(context.Background()); err != nil {
			return err
		}
	}
	return nil
}
