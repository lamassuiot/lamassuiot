package postgrestest

import (
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	postgres "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
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

func TestMigratingVAMigratesCAAndKMSFirst(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgres.VA_SCHEMA}, false)
	defer suite.AfterSuite()
	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "VA dependencies")
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.VA_SCHEMA))
	var valid bool
	require.NoError(t, suite.DB[postgres.VA_SCHEMA].Raw(`SELECT convalidated FROM pg_constraint WHERE conrelid = 'va.va_role'::regclass AND conname = 'va_role_signer_certificate_fk'`).Scan(&valid).Error)
	require.True(t, valid)
}
