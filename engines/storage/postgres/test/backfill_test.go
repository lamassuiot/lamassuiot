package postgrestest

import (
	"context"
	"fmt"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	postgres "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
	"github.com/stretchr/testify/require"
)

const defaultTenantID = "00000000-0000-0000-0000-000000000002"

func TestTenantBackfillAssignsHistoricalRows(t *testing.T) {
	_, suite := BeforeSuite([]string{postgres.DEVICE_DB_NAME}, false)
	defer suite.AfterSuite()

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Tenant backfill test")
	migrator := postgres.NewMigrator(logger, suite.DB[postgres.DEVICE_DB_NAME])

	_, err := migrator.Goose.UpTo(context.Background(), 20260120114736)
	require.NoError(t, err)
	require.NoError(t, suite.DB[postgres.DEVICE_DB_NAME].Exec(`
		INSERT INTO devices (id, status) VALUES (?, ?)
	`, "historical-device", "ACTIVE").Error)

	_, err = migrator.Goose.UpTo(context.Background(), 20260918130000)
	require.NoError(t, err)

	var tenantID string
	require.NoError(t, suite.DB[postgres.DEVICE_DB_NAME].
		Raw("SELECT tenant_id FROM devices WHERE id = ?", "historical-device").
		Scan(&tenantID).Error)
	require.Equal(t, defaultTenantID, tenantID)

	var nullRows int64
	require.NoError(t, suite.DB[postgres.DEVICE_DB_NAME].
		Raw("SELECT count(*) FROM devices WHERE tenant_id IS NULL").
		Scan(&nullRows).Error)
	require.Zero(t, nullRows)
}

func TestTenantBackfillReconciliation(t *testing.T) {
	databaseTables := map[string][]string{
		postgres.CA_DB_NAME:     {"ca_certificates", "certificates", "issuance_profiles"},
		postgres.DEVICE_DB_NAME: {"devices", "device_groups"},
		postgres.DMS_DB_NAME:    {"dms"},
		postgres.ALERTS_DB_NAME: {"subscriptions"},
		postgres.VA_DB_NAME:     {"va_role"},
		postgres.KMS_DB_NAME:    {"kms_keys"},
	}
	databaseNames := make([]string, 0, len(databaseTables))
	for databaseName := range databaseTables {
		databaseNames = append(databaseNames, databaseName)
	}

	cfg, suite := BeforeSuite(databaseNames, false)
	defer suite.AfterSuite()

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Tenant backfill reconciliation")
	require.NoError(t, postgres.MigrateAllDatabases(logger, cfg))

	for databaseName, tables := range databaseTables {
		for _, tableName := range tables {
			var nullRows int64
			require.NoError(t, suite.DB[databaseName].
				Raw(fmt.Sprintf("SELECT count(*) FROM %s WHERE tenant_id IS NULL", tableName)).
				Scan(&nullRows).Error)
			require.Zero(t, nullRows, "%s.%s contains rows without tenant_id", databaseName, tableName)
		}
	}
}

func TestTenantConstraintsRejectCrossTenantCAReferences(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgres.CA_DB_NAME}, false)
	defer suite.AfterSuite()

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Tenant constraint test")
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.CA_DB_NAME))
	db := suite.DB[postgres.CA_DB_NAME]

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
