package postgrestest

import (
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	postgres "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The CA schema cannot be migrated without the KMS one, so migrating it migrates the KMS first.
func TestMigratingCAMigratesKMSFirst(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgres.CA_SCHEMA}, false)
	defer suite.AfterSuite()

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Test")
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.CA_SCHEMA))

	var keysTable *string
	require.NoError(t, suite.DB[postgres.CA_SCHEMA].Raw(`SELECT to_regclass('kms.kms_keys')::text`).Scan(&keysTable).Error)
	require.NotNil(t, keysTable)
	assert.Equal(t, "kms.kms_keys", *keysTable)
}

// MigrateAllSchemas already runs the schemas in dependency order, so a dependency must not be migrated
// again when the schema that needs it comes up.
func TestMigrateAllSchemasMigratesEachSchemaOnce(t *testing.T) {
	schemas := postgres.MigrationSchemaOrder()
	cfg, suite := BeforeSuite(schemas, false)
	defer suite.AfterSuite()

	l := logrus.New()
	hook := logtest.NewLocal(l)
	require.NoError(t, postgres.MigrateAllSchemas(logrus.NewEntry(l), cfg))

	for _, schema := range schemas {
		runs := 0
		for _, entry := range hook.AllEntries() {
			if entry.Message == "Starting migration for schema: "+schema {
				runs++
			}
		}
		assert.Equal(t, 1, runs, "schema %s", schema)
	}
}

// Every migration opens its own connection pool; it has to be closed once the migration is done.
func TestMigrateSchemaClosesItsConnections(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgres.VA_SCHEMA}, false)
	defer suite.AfterSuite()

	openConnections := func() int64 {
		var n int64
		require.NoError(t, suite.DB[postgres.VA_SCHEMA].Raw(
			`SELECT count(*) FROM pg_stat_activity WHERE datname = 'pki' AND backend_type = 'client backend'`).Scan(&n).Error)
		return n
	}
	before := openConnections()

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Test")
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.VA_SCHEMA))

	assert.Eventually(t, func() bool { return openConnections() == before }, 5*time.Second, 100*time.Millisecond,
		"migration left connections open: before=%d, now=%d", before, openConnections())
}

func TestMigratingVAMigratesCAAndKMSFirst(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgres.VA_SCHEMA}, false)
	defer suite.AfterSuite()
	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "VA dependencies")
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.VA_SCHEMA))
	var valid bool
	require.NoError(t, suite.DB[postgres.VA_SCHEMA].Raw(`SELECT convalidated FROM pg_constraint WHERE conrelid = 'va.crl_settings'::regclass AND conname = 'crl_settings_signer_cert_fk'`).Scan(&valid).Error)
	require.True(t, valid)
}
