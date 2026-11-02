package postgrestest

import (
	"fmt"
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

func TestTenantBackfillReconciliation(t *testing.T) {
	schemaTables := map[string][]string{
		postgres.CA_SCHEMA:     {"ca_certificates", "certificates", "issuance_profiles"},
		postgres.DEVICE_SCHEMA: {"devices", "device_groups", "device_events"},
		postgres.DMS_SCHEMA:    {"dms"},
		postgres.ALERTS_SCHEMA: {"subscriptions", "events"},
		postgres.VA_SCHEMA:     {"va_role"},
		postgres.KMS_SCHEMA:    {"kms_keys"},
	}
	schemaNames := []string{postgres.CONTROLPLANE_SCHEMA}
	for schemaName := range schemaTables {
		schemaNames = append(schemaNames, schemaName)
	}

	cfg, suite := BeforeSuite(schemaNames, false)
	defer suite.AfterSuite()

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Tenant backfill reconciliation")
	require.NoError(t, postgres.MigrateAllSchemas(logger, cfg))

	for schemaName, tables := range schemaTables {
		for _, tableName := range tables {
			var nullRows int64
			require.NoError(t, suite.DB[schemaName].
				Raw(fmt.Sprintf("SELECT count(*) FROM %s WHERE tenant_id IS NULL", tableName)).
				Scan(&nullRows).Error)
			require.Zero(t, nullRows, "%s.%s contains rows without tenant_id", schemaName, tableName)
		}
	}
}
