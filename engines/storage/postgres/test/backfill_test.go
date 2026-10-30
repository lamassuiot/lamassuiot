package postgrestest

import (
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	postgres "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"github.com/stretchr/testify/require"
)

func TestTenantConstraintsRejectCrossTenantCAReferences(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgres.CA_SCHEMA}, false)
	defer suite.AfterSuite()

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Tenant constraint test")
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.CA_SCHEMA))
	db := suite.DB[postgres.CA_SCHEMA]

	require.NoError(t, db.Exec(
		"INSERT INTO certificates (serial_number, tenant_id) VALUES (?, ?)",
		"serial-a", "tenant-a",
	).Error)

	err := db.Exec(
		"INSERT INTO ca_certificates (serial_number, id, tenant_id) VALUES (?, ?, ?)",
		"serial-a", "ca-b", "tenant-b",
	).Error
	require.Error(t, err)
}
