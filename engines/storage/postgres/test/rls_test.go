package postgrestest

import (
	"context"
	"fmt"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	postgresstorage "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestTenantRLSUsesTransactionTenantAsApplicationRole(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgresstorage.ALERTS_DB_NAME}, false)
	defer suite.AfterSuite()

	require.NoError(t, postgresstorage.MigrateDatabase(helpers.SetupLogger(config.Info, "PostgreSQL", "RLS test"), cfg, postgresstorage.ALERTS_DB_NAME))

	adminDB := suite.DB[postgresstorage.ALERTS_DB_NAME]
	require.NoError(t, adminDB.Exec("ALTER ROLE lamassu_app PASSWORD 'rls-test'").Error)

	appDB, err := gorm.Open(postgres.Open(fmt.Sprintf(
		"host=%s port=%d user=lamassu_app dbname=%s password=rls-test sslmode=disable",
		cfg.Hostname, cfg.Port, postgresstorage.ALERTS_DB_NAME,
	)), &gorm.Config{})
	require.NoError(t, err)

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

	require.Equal(t, int64(1), countSubscriptions(testTenantContext("tenant-a")))
	require.Equal(t, int64(1), countSubscriptions(testTenantContext("tenant-b")))

	err = postgresstorage.WithTenantTransaction(testTenantContext("tenant-a"), appDB, func(tx *gorm.DB) error {
		return tx.Exec("INSERT INTO subscriptions (id, tenant_id) VALUES (?, ?)", "subscription-cross-tenant", "tenant-b").Error
	})
	require.Error(t, err)

	err = postgresstorage.WithTenantTransaction(testTenantContext("tenant-a"), appDB, func(tx *gorm.DB) error {
		result := tx.Exec("UPDATE subscriptions SET channel = ? WHERE id = ?", "blocked", "subscription-b")
		require.NoError(t, result.Error)
		require.Zero(t, result.RowsAffected)
		return nil
	})
	require.NoError(t, err)

	err = postgresstorage.WithTenantTransaction(testTenantContext("tenant-a"), appDB, func(tx *gorm.DB) error {
		return tx.Exec("UPDATE subscriptions SET tenant_id = ? WHERE id = ?", "tenant-b", "subscription-a").Error
	})
	require.Error(t, err)

	err = postgresstorage.WithTenantTransaction(testTenantContext("tenant-a"), appDB, func(tx *gorm.DB) error {
		result := tx.Exec("DELETE FROM subscriptions WHERE id = ?", "subscription-b")
		require.NoError(t, result.Error)
		require.Zero(t, result.RowsAffected)
		return nil
	})
	require.NoError(t, err)
}

func TestTenantRLSScopesCountsAndPagination(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgresstorage.ALERTS_DB_NAME}, false)
	defer suite.AfterSuite()

	require.NoError(t, postgresstorage.MigrateDatabase(helpers.SetupLogger(config.Info, "PostgreSQL", "RLS pagination test"), cfg, postgresstorage.ALERTS_DB_NAME))

	adminDB := suite.DB[postgresstorage.ALERTS_DB_NAME]
	require.NoError(t, adminDB.Exec("ALTER ROLE lamassu_app PASSWORD 'rls-pagination-test'").Error)
	require.NoError(t, adminDB.Exec("INSERT INTO subscriptions (id, tenant_id, channel) VALUES (?, ?, ?), (?, ?, ?), (?, ?, ?), (?, ?, ?)",
		"subscription-a-1", "tenant-a", "a-1", "subscription-a-2", "tenant-a", "a-2",
		"subscription-b-1", "tenant-b", "b-1", "subscription-b-2", "tenant-b", "b-2").Error)

	appDB, err := gorm.Open(postgres.Open(fmt.Sprintf(
		"host=%s port=%d user=lamassu_app dbname=%s password=rls-pagination-test sslmode=disable",
		cfg.Hostname, cfg.Port, postgresstorage.ALERTS_DB_NAME,
	)), &gorm.Config{})
	require.NoError(t, err)

	var channels []string
	err = postgresstorage.WithTenantTransaction(testTenantContext("tenant-a"), appDB, func(tx *gorm.DB) error {
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
	err = postgresstorage.WithTenantTransaction(testTenantContext("tenant-b"), appDB, func(tx *gorm.DB) error {
		return tx.Table("subscriptions").Order("channel ASC").Offset(1).Limit(1).Pluck("channel", &channels).Error
	})
	require.NoError(t, err)
	require.Equal(t, []string{"b-2"}, channels)
}

func TestVATenantRLSUsesCompositeTenantKey(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgresstorage.VA_DB_NAME}, false)
	defer suite.AfterSuite()

	require.NoError(t, postgresstorage.MigrateDatabase(helpers.SetupLogger(config.Info, "PostgreSQL", "VA RLS test"), cfg, postgresstorage.VA_DB_NAME))

	adminDB := suite.DB[postgresstorage.VA_DB_NAME]
	require.NoError(t, adminDB.Exec("ALTER ROLE lamassu_app PASSWORD 'va-rls-test'").Error)

	appDB, err := gorm.Open(postgres.Open(fmt.Sprintf(
		"host=%s port=%d user=lamassu_app dbname=%s password=va-rls-test sslmode=disable",
		cfg.Hostname, cfg.Port, postgresstorage.VA_DB_NAME,
	)), &gorm.Config{})
	require.NoError(t, err)

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

	require.Equal(t, int64(1), countRoles(testTenantContext("tenant-a")))
	require.Equal(t, int64(1), countRoles(testTenantContext("tenant-b")))

	err = postgresstorage.WithTenantTransaction(testTenantContext("tenant-a"), appDB, func(tx *gorm.DB) error {
		return tx.Exec("INSERT INTO va_role (tenant_id, ca_ski) VALUES (?, ?)", "tenant-b", "cross-tenant-ca").Error
	})
	require.Error(t, err)

	err = postgresstorage.WithTenantTransaction(testTenantContext("tenant-a"), appDB, func(tx *gorm.DB) error {
		result := tx.Exec("UPDATE va_role SET ca_ski = ? WHERE tenant_id = ? AND ca_ski = ?", "changed-ca-ski", "tenant-b", "shared-ca-ski")
		require.NoError(t, result.Error)
		require.Zero(t, result.RowsAffected)
		return nil
	})
	require.NoError(t, err)

	err = postgresstorage.WithTenantTransaction(testTenantContext("tenant-a"), appDB, func(tx *gorm.DB) error {
		result := tx.Exec("DELETE FROM va_role WHERE tenant_id = ? AND ca_ski = ?", "tenant-b", "shared-ca-ski")
		require.NoError(t, result.Error)
		require.Zero(t, result.RowsAffected)
		return nil
	})
	require.NoError(t, err)
}

func TestDMSTenantRLSPreventsCrossTenantAccess(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgresstorage.DMS_DB_NAME}, false)
	defer suite.AfterSuite()

	require.NoError(t, postgresstorage.MigrateDatabase(helpers.SetupLogger(config.Info, "PostgreSQL", "DMS RLS test"), cfg, postgresstorage.DMS_DB_NAME))

	adminDB := suite.DB[postgresstorage.DMS_DB_NAME]
	require.NoError(t, adminDB.Exec("ALTER ROLE lamassu_app PASSWORD 'dms-rls-test'").Error)

	appDB, err := gorm.Open(postgres.Open(fmt.Sprintf(
		"host=%s port=%d user=lamassu_app dbname=%s password=dms-rls-test sslmode=disable",
		cfg.Hostname, cfg.Port, postgresstorage.DMS_DB_NAME,
	)), &gorm.Config{})
	require.NoError(t, err)

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

	require.Equal(t, int64(1), countDMS(testTenantContext("tenant-a")))
	require.Equal(t, int64(1), countDMS(testTenantContext("tenant-b")))

	err = postgresstorage.WithTenantTransaction(testTenantContext("tenant-a"), appDB, func(tx *gorm.DB) error {
		return tx.Exec("INSERT INTO dms (id, name, tenant_id) VALUES (?, ?, ?)", "dms-cross", "Cross tenant", "tenant-b").Error
	})
	require.Error(t, err)

	err = postgresstorage.WithTenantTransaction(testTenantContext("tenant-a"), appDB, func(tx *gorm.DB) error {
		result := tx.Exec("UPDATE dms SET name = ? WHERE id = ?", "changed", "dms-b")
		require.NoError(t, result.Error)
		require.Zero(t, result.RowsAffected)
		return nil
	})
	require.NoError(t, err)

	err = postgresstorage.WithTenantTransaction(testTenantContext("tenant-a"), appDB, func(tx *gorm.DB) error {
		result := tx.Exec("DELETE FROM dms WHERE id = ?", "dms-b")
		require.NoError(t, result.Error)
		require.Zero(t, result.RowsAffected)
		return nil
	})
	require.NoError(t, err)
}

func TestKMSTenantRLSPreventsCrossTenantAccess(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgresstorage.KMS_DB_NAME}, false)
	defer suite.AfterSuite()

	require.NoError(t, postgresstorage.MigrateDatabase(helpers.SetupLogger(config.Info, "PostgreSQL", "KMS RLS test"), cfg, postgresstorage.KMS_DB_NAME))

	adminDB := suite.DB[postgresstorage.KMS_DB_NAME]
	require.NoError(t, adminDB.Exec("ALTER ROLE lamassu_app PASSWORD 'kms-rls-test'").Error)

	appDB, err := gorm.Open(postgres.Open(fmt.Sprintf(
		"host=%s port=%d user=lamassu_app dbname=%s password=kms-rls-test sslmode=disable",
		cfg.Hostname, cfg.Port, postgresstorage.KMS_DB_NAME,
	)), &gorm.Config{})
	require.NoError(t, err)

	require.NoError(t, adminDB.Exec("INSERT INTO kms_keys (key_id, name, algorithm, size, public_key, tenant_id) VALUES (?, ?, ?, ?, ?, ?), (?, ?, ?, ?, ?, ?)",
		"key-a", "Key A", "RSA", 2048, "public-a", "tenant-a", "key-b", "Key B", "RSA", 2048, "public-b", "tenant-b").Error)

	countKeys := func(ctx context.Context) int64 {
		var count int64
		txErr := postgresstorage.WithTenantTransaction(ctx, appDB, func(tx *gorm.DB) error {
			return tx.Raw("SELECT count(*) FROM kms_keys").Scan(&count).Error
		})
		require.NoError(t, txErr)
		return count
	}

	require.Equal(t, int64(1), countKeys(testTenantContext("tenant-a")))
	require.Equal(t, int64(1), countKeys(testTenantContext("tenant-b")))

	err = postgresstorage.WithTenantTransaction(testTenantContext("tenant-a"), appDB, func(tx *gorm.DB) error {
		return tx.Exec("INSERT INTO kms_keys (key_id, name, algorithm, size, public_key, tenant_id) VALUES (?, ?, ?, ?, ?, ?)", "key-cross", "Cross tenant", "RSA", 2048, "public-cross", "tenant-b").Error
	})
	require.Error(t, err)

	err = postgresstorage.WithTenantTransaction(testTenantContext("tenant-a"), appDB, func(tx *gorm.DB) error {
		result := tx.Exec("UPDATE kms_keys SET name = ? WHERE key_id = ?", "changed", "key-b")
		require.NoError(t, result.Error)
		require.Zero(t, result.RowsAffected)
		return nil
	})
	require.NoError(t, err)

	err = postgresstorage.WithTenantTransaction(testTenantContext("tenant-a"), appDB, func(tx *gorm.DB) error {
		result := tx.Exec("DELETE FROM kms_keys WHERE key_id = ?", "key-b")
		require.NoError(t, result.Error)
		require.Zero(t, result.RowsAffected)
		return nil
	})
	require.NoError(t, err)
}

func TestDeviceTenantRLSPreventsCrossTenantAccess(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgresstorage.DEVICE_DB_NAME}, false)
	defer suite.AfterSuite()

	require.NoError(t, postgresstorage.MigrateDatabase(helpers.SetupLogger(config.Info, "PostgreSQL", "Device RLS test"), cfg, postgresstorage.DEVICE_DB_NAME))

	adminDB := suite.DB[postgresstorage.DEVICE_DB_NAME]
	require.NoError(t, adminDB.Exec("ALTER ROLE lamassu_app PASSWORD 'device-rls-test'").Error)

	appDB, err := gorm.Open(postgres.Open(fmt.Sprintf(
		"host=%s port=%d user=lamassu_app dbname=%s password=device-rls-test sslmode=disable",
		cfg.Hostname, cfg.Port, postgresstorage.DEVICE_DB_NAME,
	)), &gorm.Config{})
	require.NoError(t, err)

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

	require.Equal(t, int64(1), countDevices(testTenantContext("tenant-a")))
	require.Equal(t, int64(1), countDevices(testTenantContext("tenant-b")))

	err = postgresstorage.WithTenantTransaction(testTenantContext("tenant-a"), appDB, func(tx *gorm.DB) error {
		return tx.Exec("INSERT INTO devices (id, tenant_id) VALUES (?, ?)", "device-cross", "tenant-b").Error
	})
	require.Error(t, err)

	err = postgresstorage.WithTenantTransaction(testTenantContext("tenant-a"), appDB, func(tx *gorm.DB) error {
		result := tx.Exec("UPDATE devices SET tenant_id = ? WHERE id = ?", "tenant-b", "device-a")
		return result.Error
	})
	require.Error(t, err)

	err = postgresstorage.WithTenantTransaction(testTenantContext("tenant-a"), appDB, func(tx *gorm.DB) error {
		result := tx.Exec("DELETE FROM devices WHERE id = ?", "device-b")
		require.NoError(t, result.Error)
		require.Zero(t, result.RowsAffected)
		return nil
	})
	require.NoError(t, err)
}

func TestCATenantRLSPreventsCrossTenantAccess(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgresstorage.CA_DB_NAME}, false)
	defer suite.AfterSuite()

	require.NoError(t, postgresstorage.MigrateDatabase(helpers.SetupLogger(config.Info, "PostgreSQL", "CA RLS test"), cfg, postgresstorage.CA_DB_NAME))

	adminDB := suite.DB[postgresstorage.CA_DB_NAME]
	require.NoError(t, adminDB.Exec("ALTER ROLE lamassu_app PASSWORD 'ca-rls-test'").Error)

	appDB, err := gorm.Open(postgres.Open(fmt.Sprintf(
		"host=%s port=%d user=lamassu_app dbname=%s password=ca-rls-test sslmode=disable",
		cfg.Hostname, cfg.Port, postgresstorage.CA_DB_NAME,
	)), &gorm.Config{})
	require.NoError(t, err)

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

	require.Equal(t, int64(1), countCAs(testTenantContext("tenant-a")))
	require.Equal(t, int64(1), countCAs(testTenantContext("tenant-b")))

	err = postgresstorage.WithTenantTransaction(testTenantContext("tenant-a"), appDB, func(tx *gorm.DB) error {
		return tx.Exec("INSERT INTO ca_certificates (serial_number, id, tenant_id) VALUES (?, ?, ?)", "serial-cross", "ca-cross", "tenant-b").Error
	})
	require.Error(t, err)

	err = postgresstorage.WithTenantTransaction(testTenantContext("tenant-a"), appDB, func(tx *gorm.DB) error {
		result := tx.Exec("UPDATE ca_certificates SET id = ? WHERE serial_number = ?", "changed-ca", "serial-b")
		require.NoError(t, result.Error)
		require.Zero(t, result.RowsAffected)
		return nil
	})
	require.NoError(t, err)

	err = postgresstorage.WithTenantTransaction(testTenantContext("tenant-a"), appDB, func(tx *gorm.DB) error {
		result := tx.Exec("DELETE FROM ca_certificates WHERE serial_number = ?", "serial-b")
		require.NoError(t, result.Error)
		require.Zero(t, result.RowsAffected)
		return nil
	})
	require.NoError(t, err)
}

func testTenantContext(tenantID string) context.Context {
	return core.WithTenantContext(context.Background(), core.TenantContext{
		OrganizationID: "organization",
		TenantID:       tenantID,
		ActorID:        "actor",
		ActorType:      "user",
		CorrelationID:  "correlation",
		Source:         "test",
		TenantStatus:   core.TenantActive,
		Validated:      true,
	})
}
