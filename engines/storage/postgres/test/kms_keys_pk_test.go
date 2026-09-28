package postgrestest

import (
	"fmt"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	postgresstorage "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// TestKMSKeysAllowSameKeyIDInTwoTenants comprueba que dos tenants pueden registrar la misma
// clave (mismo key_id, SHA-256 del SPKI) sin chocar entre sí (003 T13).
func TestKMSKeysAllowSameKeyIDInTwoTenants(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgresstorage.KMS_DB_NAME}, false)
	defer suite.AfterSuite()

	require.NoError(t, postgresstorage.MigrateDatabase(helpers.SetupLogger(config.Info, "PostgreSQL", "KMS PK test"), cfg, postgresstorage.KMS_DB_NAME))

	adminDB := suite.DB[postgresstorage.KMS_DB_NAME]
	require.NoError(t, adminDB.Exec("ALTER ROLE lamassu_app PASSWORD 'kms-pk-test'").Error)

	appDB, err := gorm.Open(postgres.Open(fmt.Sprintf(
		"host=%s port=%d user=lamassu_app dbname=%s password=kms-pk-test sslmode=disable",
		cfg.Hostname, cfg.Port, postgresstorage.KMS_DB_NAME,
	)), &gorm.Config{})
	require.NoError(t, err)

	const keyID = "shared-key-id"
	insertKey := func(tenantID, name string) error {
		return postgresstorage.WithTenantTransaction(testTenantContext(tenantID), appDB, func(tx *gorm.DB) error {
			return tx.Exec("INSERT INTO kms_keys (key_id, name, algorithm, size, public_key, tenant_id) VALUES (?, ?, ?, ?, ?, ?)",
				keyID, name, "RSA", 2048, "public-shared", tenantID).Error
		})
	}
	visibleNames := func(tenantID string) []string {
		var names []string
		require.NoError(t, postgresstorage.WithTenantTransaction(testTenantContext(tenantID), appDB, func(tx *gorm.DB) error {
			return tx.Raw("SELECT name FROM kms_keys WHERE key_id = ?", keyID).Scan(&names).Error
		}))
		return names
	}

	require.NoError(t, insertKey("tenant-a", "key-a"))
	require.NoError(t, insertKey("tenant-b", "key-b"))

	require.Equal(t, []string{"key-a"}, visibleNames("tenant-a"))
	require.Equal(t, []string{"key-b"}, visibleNames("tenant-b"))

	err = postgresstorage.WithTenantTransaction(testTenantContext("tenant-b"), appDB, func(tx *gorm.DB) error {
		result := tx.Exec("UPDATE kms_keys SET name = ? WHERE key_id = ?", "key-b-renamed", keyID)
		require.NoError(t, result.Error)
		require.Equal(t, int64(1), result.RowsAffected)
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, []string{"key-a"}, visibleNames("tenant-a"))
	require.Equal(t, []string{"key-b-renamed"}, visibleNames("tenant-b"))

	err = postgresstorage.WithTenantTransaction(testTenantContext("tenant-b"), appDB, func(tx *gorm.DB) error {
		result := tx.Exec("DELETE FROM kms_keys WHERE key_id = ?", keyID)
		require.NoError(t, result.Error)
		require.Equal(t, int64(1), result.RowsAffected)
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, []string{"key-a"}, visibleNames("tenant-a"))
	require.Empty(t, visibleNames("tenant-b"))

	err = insertKey("tenant-a", "key-a-duplicate")
	require.ErrorContains(t, err, "keys_pkey")
}
