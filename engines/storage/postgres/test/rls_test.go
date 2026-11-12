package postgrestest

import (
	"context"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	postgresstorage "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestTenantRLSUsesTransactionTenantAsApplicationRole(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgresstorage.ALERTS_SCHEMA}, false)
	defer suite.AfterSuite()

	require.NoError(t, postgresstorage.MigrateDatabase(helpers.SetupLogger(config.Info, "PostgreSQL", "RLS test"), cfg, postgresstorage.ALERTS_SCHEMA))

	adminDB := suite.DB[postgresstorage.ALERTS_SCHEMA]
	require.NoError(t, adminDB.Exec("ALTER ROLE lamassu_app PASSWORD 'rls-test'").Error)
	appDB := openTenantAppDB(t, cfg.Hostname, cfg.Port, postgresstorage.ALERTS_SCHEMA, "rls-test")

	require.NoError(t, adminDB.Exec("INSERT INTO subscriptions (id, tenant_id) VALUES (?, ?), (?, ?)",
		"subscription-a", "tenant-a", "subscription-b", "tenant-b").Error)

	var unscopedCount int64
	require.NoError(t, appDB.Raw("SELECT count(*) FROM subscriptions").Scan(&unscopedCount).Error)
	require.Zero(t, unscopedCount)

	countSubscriptions := func(ctx context.Context) int64 {
		var count int64
		txErr := postgresstorage.WithTenantTransaction(ctx, appDB, func(tx *gorm.DB) error {
			return tx.Raw("SELECT count(*) FROM subscriptions").Scan(&count).Error
		})
		require.NoError(t, txErr)
		return count
	}

	require.Equal(t, int64(1), countSubscriptions(tenantTestContext("tenant-a", models.TenantActive)))
	require.Equal(t, int64(1), countSubscriptions(tenantTestContext("tenant-b", models.TenantActive)))

	err := postgresstorage.WithTenantTransaction(tenantTestContext("tenant-a", models.TenantActive), appDB, func(tx *gorm.DB) error {
		return tx.Exec("INSERT INTO subscriptions (id, tenant_id) VALUES (?, ?)", "subscription-cross-tenant", "tenant-b").Error
	})
	require.Error(t, err)

	err = postgresstorage.WithTenantTransaction(tenantTestContext("tenant-a", models.TenantActive), appDB, func(tx *gorm.DB) error {
		result := tx.Exec("UPDATE subscriptions SET channel = ? WHERE id = ?", "blocked", "subscription-b")
		require.NoError(t, result.Error)
		require.Zero(t, result.RowsAffected)
		return nil
	})
	require.NoError(t, err)

	err = postgresstorage.WithTenantTransaction(tenantTestContext("tenant-a", models.TenantActive), appDB, func(tx *gorm.DB) error {
		return tx.Exec("UPDATE subscriptions SET tenant_id = ? WHERE id = ?", "tenant-b", "subscription-a").Error
	})
	require.Error(t, err)

	err = postgresstorage.WithTenantTransaction(tenantTestContext("tenant-a", models.TenantActive), appDB, func(tx *gorm.DB) error {
		result := tx.Exec("DELETE FROM subscriptions WHERE id = ?", "subscription-b")
		require.NoError(t, result.Error)
		require.Zero(t, result.RowsAffected)
		return nil
	})
	require.NoError(t, err)
}

func TestTenantRLSScopesCountsAndPagination(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgresstorage.ALERTS_SCHEMA}, false)
	defer suite.AfterSuite()

	require.NoError(t, postgresstorage.MigrateDatabase(helpers.SetupLogger(config.Info, "PostgreSQL", "RLS pagination test"), cfg, postgresstorage.ALERTS_SCHEMA))

	adminDB := suite.DB[postgresstorage.ALERTS_SCHEMA]
	require.NoError(t, adminDB.Exec("ALTER ROLE lamassu_app PASSWORD 'rls-pagination-test'").Error)
	require.NoError(t, adminDB.Exec("INSERT INTO subscriptions (id, tenant_id, channel) VALUES (?, ?, ?), (?, ?, ?), (?, ?, ?), (?, ?, ?)",
		"subscription-a-1", "tenant-a", "a-1", "subscription-a-2", "tenant-a", "a-2",
		"subscription-b-1", "tenant-b", "b-1", "subscription-b-2", "tenant-b", "b-2").Error)

	appDB := openTenantAppDB(t, cfg.Hostname, cfg.Port, postgresstorage.ALERTS_SCHEMA, "rls-pagination-test")

	var channels []string
	err := postgresstorage.WithTenantTransaction(tenantTestContext("tenant-a", models.TenantActive), appDB, func(tx *gorm.DB) error {
		var count int64
		if err := tx.Model(&struct{}{}).Table("subscriptions").Count(&count).Error; err != nil {
			return err
		}
		require.Equal(t, int64(2), count)
		return tx.Table("subscriptions").Order("channel ASC").Offset(0).Limit(1).Pluck("channel", &channels).Error
	})
	require.NoError(t, err)
	require.Equal(t, []string{"a-1"}, channels)

	channels = nil
	err = postgresstorage.WithTenantTransaction(tenantTestContext("tenant-b", models.TenantActive), appDB, func(tx *gorm.DB) error {
		return tx.Table("subscriptions").Order("channel ASC").Offset(1).Limit(1).Pluck("channel", &channels).Error
	})
	require.NoError(t, err)
	require.Equal(t, []string{"b-2"}, channels)
}

func TestVATenantRLSUsesCompositeTenantKey(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgresstorage.VA_SCHEMA}, false)
	defer suite.AfterSuite()

	require.NoError(t, postgresstorage.MigrateDatabase(helpers.SetupLogger(config.Info, "PostgreSQL", "VA RLS test"), cfg, postgresstorage.VA_SCHEMA))

	adminDB := suite.DB[postgresstorage.VA_SCHEMA]
	require.NoError(t, adminDB.Exec("ALTER ROLE lamassu_app PASSWORD 'va-rls-test'").Error)
	appDB := openTenantAppDB(t, cfg.Hostname, cfg.Port, postgresstorage.VA_SCHEMA, "va-rls-test")

	require.NoError(t, adminDB.Exec("INSERT INTO va_role (tenant_id, ca_ski) VALUES (?, ?), (?, ?)",
		"tenant-a", "shared-ca-ski", "tenant-b", "shared-ca-ski").Error)

	countRoles := func(ctx context.Context) int64 {
		var count int64
		txErr := postgresstorage.WithTenantTransaction(ctx, appDB, func(tx *gorm.DB) error {
			return tx.Raw("SELECT count(*) FROM va_role").Scan(&count).Error
		})
		require.NoError(t, txErr)
		return count
	}

	require.Equal(t, int64(1), countRoles(tenantTestContext("tenant-a", models.TenantActive)))
	require.Equal(t, int64(1), countRoles(tenantTestContext("tenant-b", models.TenantActive)))

	err := postgresstorage.WithTenantTransaction(tenantTestContext("tenant-a", models.TenantActive), appDB, func(tx *gorm.DB) error {
		return tx.Exec("INSERT INTO va_role (tenant_id, ca_ski) VALUES (?, ?)", "tenant-b", "cross-tenant-ca").Error
	})
	require.Error(t, err)

	err = postgresstorage.WithTenantTransaction(tenantTestContext("tenant-a", models.TenantActive), appDB, func(tx *gorm.DB) error {
		result := tx.Exec("UPDATE va_role SET ca_ski = ? WHERE tenant_id = ? AND ca_ski = ?", "changed-ca-ski", "tenant-b", "shared-ca-ski")
		require.NoError(t, result.Error)
		require.Zero(t, result.RowsAffected)
		return nil
	})
	require.NoError(t, err)

	err = postgresstorage.WithTenantTransaction(tenantTestContext("tenant-a", models.TenantActive), appDB, func(tx *gorm.DB) error {
		result := tx.Exec("DELETE FROM va_role WHERE tenant_id = ? AND ca_ski = ?", "tenant-b", "shared-ca-ski")
		require.NoError(t, result.Error)
		require.Zero(t, result.RowsAffected)
		return nil
	})
	require.NoError(t, err)
}

func TestDMSTenantRLSPreventsCrossTenantAccess(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgresstorage.DMS_SCHEMA}, false)
	defer suite.AfterSuite()

	require.NoError(t, postgresstorage.MigrateDatabase(helpers.SetupLogger(config.Info, "PostgreSQL", "DMS RLS test"), cfg, postgresstorage.DMS_SCHEMA))

	adminDB := suite.DB[postgresstorage.DMS_SCHEMA]
	require.NoError(t, adminDB.Exec("ALTER ROLE lamassu_app PASSWORD 'dms-rls-test'").Error)
	appDB := openTenantAppDB(t, cfg.Hostname, cfg.Port, postgresstorage.DMS_SCHEMA, "dms-rls-test")

	require.NoError(t, adminDB.Exec("INSERT INTO dms (id, name, tenant_id) VALUES (?, ?, ?), (?, ?, ?)",
		"dms-a", "DMS A", "tenant-a", "dms-b", "DMS B", "tenant-b").Error)

	countDMS := func(ctx context.Context) int64 {
		var count int64
		txErr := postgresstorage.WithTenantTransaction(ctx, appDB, func(tx *gorm.DB) error {
			return tx.Raw("SELECT count(*) FROM dms").Scan(&count).Error
		})
		require.NoError(t, txErr)
		return count
	}

	require.Equal(t, int64(1), countDMS(tenantTestContext("tenant-a", models.TenantActive)))
	require.Equal(t, int64(1), countDMS(tenantTestContext("tenant-b", models.TenantActive)))

	err := postgresstorage.WithTenantTransaction(tenantTestContext("tenant-a", models.TenantActive), appDB, func(tx *gorm.DB) error {
		return tx.Exec("INSERT INTO dms (id, name, tenant_id) VALUES (?, ?, ?)", "dms-cross", "Cross tenant", "tenant-b").Error
	})
	require.Error(t, err)

	err = postgresstorage.WithTenantTransaction(tenantTestContext("tenant-a", models.TenantActive), appDB, func(tx *gorm.DB) error {
		result := tx.Exec("UPDATE dms SET name = ? WHERE id = ?", "changed", "dms-b")
		require.NoError(t, result.Error)
		require.Zero(t, result.RowsAffected)
		return nil
	})
	require.NoError(t, err)

	err = postgresstorage.WithTenantTransaction(tenantTestContext("tenant-a", models.TenantActive), appDB, func(tx *gorm.DB) error {
		result := tx.Exec("DELETE FROM dms WHERE id = ?", "dms-b")
		require.NoError(t, result.Error)
		require.Zero(t, result.RowsAffected)
		return nil
	})
	require.NoError(t, err)
}

func TestKMSTenantRLSPreventsCrossTenantAccess(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgresstorage.KMS_SCHEMA}, false)
	defer suite.AfterSuite()

	require.NoError(t, postgresstorage.MigrateDatabase(helpers.SetupLogger(config.Info, "PostgreSQL", "KMS RLS test"), cfg, postgresstorage.KMS_SCHEMA))

	adminDB := suite.DB[postgresstorage.KMS_SCHEMA]
	require.NoError(t, adminDB.Exec("ALTER ROLE lamassu_app PASSWORD 'kms-rls-test'").Error)
	appDB := openTenantAppDB(t, cfg.Hostname, cfg.Port, postgresstorage.KMS_SCHEMA, "kms-rls-test")

	require.NoError(t, adminDB.Exec("INSERT INTO kms_keys (key_id, engine_id, name, algorithm, size, public_key, tenant_id) VALUES (?, ?, ?, ?, ?, ?, ?), (?, ?, ?, ?, ?, ?, ?)",
		"key-a", "engine-test", "Key A", "RSA", 2048, "public-a", "tenant-a", "key-b", "engine-test", "Key B", "RSA", 2048, "public-b", "tenant-b").Error)

	countKeys := func(ctx context.Context) int64 {
		var count int64
		txErr := postgresstorage.WithTenantTransaction(ctx, appDB, func(tx *gorm.DB) error {
			return tx.Raw("SELECT count(*) FROM kms_keys").Scan(&count).Error
		})
		require.NoError(t, txErr)
		return count
	}

	require.Equal(t, int64(1), countKeys(tenantTestContext("tenant-a", models.TenantActive)))
	require.Equal(t, int64(1), countKeys(tenantTestContext("tenant-b", models.TenantActive)))

	err := postgresstorage.WithTenantTransaction(tenantTestContext("tenant-a", models.TenantActive), appDB, func(tx *gorm.DB) error {
		return tx.Exec("INSERT INTO kms_keys (key_id, engine_id, name, algorithm, size, public_key, tenant_id) VALUES (?, ?, ?, ?, ?, ?, ?)", "key-cross", "engine-test", "Cross tenant", "RSA", 2048, "public-cross", "tenant-b").Error
	})
	require.Error(t, err)

	err = postgresstorage.WithTenantTransaction(tenantTestContext("tenant-a", models.TenantActive), appDB, func(tx *gorm.DB) error {
		result := tx.Exec("UPDATE kms_keys SET name = ? WHERE key_id = ?", "changed", "key-b")
		require.NoError(t, result.Error)
		require.Zero(t, result.RowsAffected)
		return nil
	})
	require.NoError(t, err)

	err = postgresstorage.WithTenantTransaction(tenantTestContext("tenant-a", models.TenantActive), appDB, func(tx *gorm.DB) error {
		result := tx.Exec("DELETE FROM kms_keys WHERE key_id = ?", "key-b")
		require.NoError(t, result.Error)
		require.Zero(t, result.RowsAffected)
		return nil
	})
	require.NoError(t, err)
}

func TestDeviceTenantRLSPreventsCrossTenantAccess(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgresstorage.DEVICE_SCHEMA}, false)
	defer suite.AfterSuite()

	require.NoError(t, postgresstorage.MigrateDatabase(helpers.SetupLogger(config.Info, "PostgreSQL", "Device RLS test"), cfg, postgresstorage.DEVICE_SCHEMA))

	adminDB := suite.DB[postgresstorage.DEVICE_SCHEMA]
	require.NoError(t, adminDB.Exec("ALTER ROLE lamassu_app PASSWORD 'device-rls-test'").Error)
	appDB := openTenantAppDB(t, cfg.Hostname, cfg.Port, postgresstorage.DEVICE_SCHEMA, "device-rls-test")

	require.NoError(t, adminDB.Exec("INSERT INTO devices (id, tenant_id) VALUES (?, ?), (?, ?)",
		"device-a", "tenant-a", "device-b", "tenant-b").Error)

	countDevices := func(ctx context.Context) int64 {
		var count int64
		txErr := postgresstorage.WithTenantTransaction(ctx, appDB, func(tx *gorm.DB) error {
			return tx.Raw("SELECT count(*) FROM devices").Scan(&count).Error
		})
		require.NoError(t, txErr)
		return count
	}

	require.Equal(t, int64(1), countDevices(tenantTestContext("tenant-a", models.TenantActive)))
	require.Equal(t, int64(1), countDevices(tenantTestContext("tenant-b", models.TenantActive)))

	err := postgresstorage.WithTenantTransaction(tenantTestContext("tenant-a", models.TenantActive), appDB, func(tx *gorm.DB) error {
		return tx.Exec("INSERT INTO devices (id, tenant_id) VALUES (?, ?)", "device-cross", "tenant-b").Error
	})
	require.Error(t, err)

	err = postgresstorage.WithTenantTransaction(tenantTestContext("tenant-a", models.TenantActive), appDB, func(tx *gorm.DB) error {
		result := tx.Exec("UPDATE devices SET tenant_id = ? WHERE id = ?", "tenant-b", "device-a")
		return result.Error
	})
	require.Error(t, err)

	err = postgresstorage.WithTenantTransaction(tenantTestContext("tenant-a", models.TenantActive), appDB, func(tx *gorm.DB) error {
		result := tx.Exec("DELETE FROM devices WHERE id = ?", "device-b")
		require.NoError(t, result.Error)
		require.Zero(t, result.RowsAffected)
		return nil
	})
	require.NoError(t, err)
}

func TestCATenantRLSPreventsCrossTenantAccess(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgresstorage.CA_SCHEMA}, false)
	defer suite.AfterSuite()

	require.NoError(t, postgresstorage.MigrateDatabase(helpers.SetupLogger(config.Info, "PostgreSQL", "CA RLS test"), cfg, postgresstorage.CA_SCHEMA))

	adminDB := suite.DB[postgresstorage.CA_SCHEMA]
	require.NoError(t, adminDB.Exec("ALTER ROLE lamassu_app PASSWORD 'ca-rls-test'").Error)
	appDB := openTenantAppDB(t, cfg.Hostname, cfg.Port, postgresstorage.CA_SCHEMA, "ca-rls-test")

	require.NoError(t, adminDB.Exec("INSERT INTO certificates (serial_number, tenant_id) VALUES (?, ?), (?, ?), (?, ?)",
		"serial-a", "tenant-a", "serial-b", "tenant-b", "serial-cross", "tenant-b").Error)
	require.NoError(t, adminDB.Exec("INSERT INTO ca_certificates (serial_number, id, tenant_id) VALUES (?, ?, ?), (?, ?, ?)",
		"serial-a", "ca-a", "tenant-a", "serial-b", "ca-b", "tenant-b").Error)

	countCAs := func(ctx context.Context) int64 {
		var count int64
		txErr := postgresstorage.WithTenantTransaction(ctx, appDB, func(tx *gorm.DB) error {
			return tx.Raw("SELECT count(*) FROM ca_certificates").Scan(&count).Error
		})
		require.NoError(t, txErr)
		return count
	}

	require.Equal(t, int64(1), countCAs(tenantTestContext("tenant-a", models.TenantActive)))
	require.Equal(t, int64(1), countCAs(tenantTestContext("tenant-b", models.TenantActive)))

	err := postgresstorage.WithTenantTransaction(tenantTestContext("tenant-a", models.TenantActive), appDB, func(tx *gorm.DB) error {
		return tx.Exec("INSERT INTO ca_certificates (serial_number, id, tenant_id) VALUES (?, ?, ?)", "serial-cross", "ca-cross", "tenant-b").Error
	})
	require.Error(t, err)

	err = postgresstorage.WithTenantTransaction(tenantTestContext("tenant-a", models.TenantActive), appDB, func(tx *gorm.DB) error {
		result := tx.Exec("UPDATE ca_certificates SET id = ? WHERE serial_number = ?", "changed-ca", "serial-b")
		require.NoError(t, result.Error)
		require.Zero(t, result.RowsAffected)
		return nil
	})
	require.NoError(t, err)

	err = postgresstorage.WithTenantTransaction(tenantTestContext("tenant-a", models.TenantActive), appDB, func(tx *gorm.DB) error {
		result := tx.Exec("DELETE FROM ca_certificates WHERE serial_number = ?", "serial-b")
		require.NoError(t, result.Error)
		require.Zero(t, result.RowsAffected)
		return nil
	})
	require.NoError(t, err)
}

func TestDeviceGroupTenantRLSPreventsCrossTenantAccess(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgresstorage.DEVICE_SCHEMA}, false)
	defer suite.AfterSuite()

	require.NoError(t, postgresstorage.MigrateDatabase(helpers.SetupLogger(config.Info, "PostgreSQL", "Device group RLS test"), cfg, postgresstorage.DEVICE_SCHEMA))

	adminDB := suite.DB[postgresstorage.DEVICE_SCHEMA]
	require.NoError(t, adminDB.Exec("ALTER ROLE lamassu_app PASSWORD 'device-group-rls-test'").Error)
	appDB := openTenantAppDB(t, cfg.Hostname, cfg.Port, postgresstorage.DEVICE_SCHEMA, "device-group-rls-test")

	const (
		rootA  = "00000000-0000-0000-0000-0000000000a1"
		childA = "00000000-0000-0000-0000-0000000000a2"
		rootB  = "00000000-0000-0000-0000-0000000000b1"
	)

	require.NoError(t, adminDB.Exec("INSERT INTO device_groups (id, name, parent_id, tenant_id) VALUES (?, ?, NULL, ?), (?, ?, ?, ?), (?, ?, NULL, ?)",
		rootA, "Factory", "tenant-a", childA, "Line 1", rootA, "tenant-a", rootB, "Factory", "tenant-b").Error)

	countGroups := func(ctx context.Context) int64 {
		var count int64
		txErr := postgresstorage.WithTenantTransaction(ctx, appDB, func(tx *gorm.DB) error {
			return tx.Raw("SELECT count(*) FROM device_groups").Scan(&count).Error
		})
		require.NoError(t, txErr)
		return count
	}

	require.Equal(t, int64(2), countGroups(tenantTestContext("tenant-a", models.TenantActive)))
	require.Equal(t, int64(1), countGroups(tenantTestContext("tenant-b", models.TenantActive)))

	ancestorsOf := func(ctx context.Context, groupID string) []string {
		var names []string
		txErr := postgresstorage.WithTenantTransaction(ctx, appDB, func(tx *gorm.DB) error {
			return tx.Raw(`
				WITH RECURSIVE ancestor_chain AS (
					SELECT id, tenant_id, name, parent_id FROM device_groups WHERE id = ?
					UNION ALL
					SELECT dg.id, dg.tenant_id, dg.name, dg.parent_id FROM device_groups dg
					INNER JOIN ancestor_chain ac ON dg.id = ac.parent_id AND dg.tenant_id = ac.tenant_id
				)
				SELECT name FROM ancestor_chain
			`, groupID).Scan(&names).Error
		})
		require.NoError(t, txErr)
		return names
	}

	require.ElementsMatch(t, []string{"Factory", "Line 1"}, ancestorsOf(tenantTestContext("tenant-a", models.TenantActive), childA))
	require.Empty(t, ancestorsOf(tenantTestContext("tenant-b", models.TenantActive), childA))

	err := postgresstorage.WithTenantTransaction(tenantTestContext("tenant-a", models.TenantActive), appDB, func(tx *gorm.DB) error {
		return tx.Exec("INSERT INTO device_groups (name, tenant_id) VALUES (?, ?)", "Cross tenant", "tenant-b").Error
	})
	require.Error(t, err)

	err = postgresstorage.WithTenantTransaction(tenantTestContext("tenant-a", models.TenantActive), appDB, func(tx *gorm.DB) error {
		return tx.Exec("INSERT INTO device_groups (name, parent_id, tenant_id) VALUES (?, ?, ?)", "Line under B", rootB, "tenant-a").Error
	})
	require.Error(t, err)

	err = postgresstorage.WithTenantTransaction(tenantTestContext("tenant-a", models.TenantActive), appDB, func(tx *gorm.DB) error {
		result := tx.Exec("DELETE FROM device_groups WHERE id = ?", rootB)
		require.NoError(t, result.Error)
		require.Zero(t, result.RowsAffected)
		return nil
	})
	require.NoError(t, err)
}

func TestDeviceEventTenantRLSPreventsCrossTenantAccess(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgresstorage.DEVICE_SCHEMA}, false)
	defer suite.AfterSuite()

	require.NoError(t, postgresstorage.MigrateDatabase(helpers.SetupLogger(config.Info, "PostgreSQL", "Device event RLS test"), cfg, postgresstorage.DEVICE_SCHEMA))

	adminDB := suite.DB[postgresstorage.DEVICE_SCHEMA]
	require.NoError(t, adminDB.Exec("ALTER ROLE lamassu_app PASSWORD 'device-event-rls-test'").Error)
	appDB := openTenantAppDB(t, cfg.Hostname, cfg.Port, postgresstorage.DEVICE_SCHEMA, "device-event-rls-test")

	require.NoError(t, adminDB.Exec("INSERT INTO devices (id, tenant_id) VALUES (?, ?), (?, ?)",
		"device-a", "tenant-a", "device-b", "tenant-b").Error)
	require.NoError(t, adminDB.Exec("INSERT INTO device_events (id, device_id, event_ts, event_type, tenant_id) VALUES (?, ?, NOW(), ?, ?), (?, ?, NOW(), ?, ?)",
		"event-a", "device-a", "created", "tenant-a", "event-b", "device-b", "created", "tenant-b").Error)

	countEvents := func(ctx context.Context) int64 {
		var count int64
		txErr := postgresstorage.WithTenantTransaction(ctx, appDB, func(tx *gorm.DB) error {
			return tx.Raw("SELECT count(*) FROM device_events").Scan(&count).Error
		})
		require.NoError(t, txErr)
		return count
	}

	require.Equal(t, int64(1), countEvents(tenantTestContext("tenant-a", models.TenantActive)))
	require.Equal(t, int64(1), countEvents(tenantTestContext("tenant-b", models.TenantActive)))

	err := postgresstorage.WithTenantTransaction(tenantTestContext("tenant-a", models.TenantActive), appDB, func(tx *gorm.DB) error {
		return tx.Exec("INSERT INTO device_events (id, device_id, event_ts, event_type, tenant_id) VALUES (?, ?, NOW(), ?, ?)",
			"event-cross", "device-b", "created", "tenant-b").Error
	})
	require.Error(t, err)

	err = postgresstorage.WithTenantTransaction(tenantTestContext("tenant-a", models.TenantActive), appDB, func(tx *gorm.DB) error {
		return tx.Exec("INSERT INTO device_events (id, device_id, event_ts, event_type, tenant_id) VALUES (?, ?, NOW(), ?, ?)",
			"event-a-on-b", "device-b", "created", "tenant-a").Error
	})
	require.Error(t, err)

	err = postgresstorage.WithTenantTransaction(tenantTestContext("tenant-a", models.TenantActive), appDB, func(tx *gorm.DB) error {
		result := tx.Exec("DELETE FROM device_events WHERE device_id = ?", "device-b")
		require.NoError(t, result.Error)
		require.Zero(t, result.RowsAffected)
		return nil
	})
	require.NoError(t, err)

	err = postgresstorage.WithTenantTransaction(tenantTestContext("tenant-b", models.TenantActive), appDB, func(tx *gorm.DB) error {
		result := tx.Exec("DELETE FROM device_events WHERE device_id = ?", "device-b")
		require.NoError(t, result.Error)
		require.Equal(t, int64(1), result.RowsAffected)
		return nil
	})
	require.NoError(t, err)
}
