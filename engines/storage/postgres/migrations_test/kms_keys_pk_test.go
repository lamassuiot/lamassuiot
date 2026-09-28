package migrationstest

import (
	"context"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
	"github.com/stretchr/testify/require"
)

const (
	kmsKeysTenantPKVersion       = int64(20260928150000)
	beforeKMSKeysTenantPKVersion = int64(20260928140000)
)

// TestKMSKeysTenantPrimaryKeyMigration comprueba que la migración cambia la PK de kms_keys a
// (tenant_id, key_id) y retira la UNIQUE redundante, y que el down restaura el estado
// anterior solo si no hay key_id repetidos entre tenants (003 T13, decisión 9).
func TestKMSKeysTenantPrimaryKeyMigration(t *testing.T) {
	logger := helpers.SetupLogger(config.Info, "test", "test")
	cleanup, con := RunDB(t, logger, postgres.KMS_DB_NAME)
	defer cleanup()

	ctx := context.Background()

	// constraints devuelve las restricciones de unicidad de kms_keys como nombre → definición.
	constraints := func() map[string]string {
		var rows []struct {
			Name string
			Def  string
		}
		require.NoError(t, con.Raw(`SELECT conname AS name, pg_get_constraintdef(oid) AS def
			FROM pg_constraint WHERE conrelid = 'kms_keys'::regclass AND contype IN ('p', 'u')`).Scan(&rows).Error)
		result := map[string]string{}
		for _, row := range rows {
			result[row.Name] = row.Def
		}
		return result
	}
	countRows := func() int64 {
		var count int64
		require.NoError(t, con.Raw("SELECT count(*) FROM kms_keys").Scan(&count).Error)
		return count
	}
	hasTenantIndex := func() bool {
		var exists bool
		require.NoError(t, con.Raw("SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE tablename = 'kms_keys' AND indexname = 'kms_keys_tenant_id_idx')").Scan(&exists).Error)
		return exists
	}
	insertKey := func(tenantID, keyID string) {
		require.NoError(t, con.Exec("INSERT INTO kms_keys (key_id, name, algorithm, size, public_key, tenant_id) VALUES (?, ?, ?, ?, ?, ?)",
			keyID, keyID, "RSA", 2048, "public", tenantID).Error)
	}
	previous := map[string]string{
		"keys_pkey":              "PRIMARY KEY (key_id)",
		"kms_keys_tenant_id_key": "UNIQUE (tenant_id, key_id)",
	}
	migrated := map[string]string{
		"keys_pkey": "PRIMARY KEY (tenant_id, key_id)",
	}

	m := postgres.NewMigrator(logger, con)
	_, err := m.Goose.UpTo(ctx, beforeKMSKeysTenantPKVersion)
	require.NoError(t, err)
	require.Equal(t, previous, constraints())

	insertKey("tenant-a", "key-1")
	insertKey("tenant-b", "key-2")

	_, err = m.Goose.UpTo(ctx, kmsKeysTenantPKVersion)
	require.NoError(t, err)
	require.Equal(t, migrated, constraints())
	require.True(t, hasTenantIndex())
	require.Equal(t, int64(2), countRows())

	// Down sin key_id repetidos entre tenants: restaura el estado anterior.
	_, err = m.Goose.DownTo(ctx, beforeKMSKeysTenantPKVersion)
	require.NoError(t, err)
	require.Equal(t, previous, constraints())
	require.True(t, hasTenantIndex())
	require.Equal(t, int64(2), countRows())

	// Down con el mismo key_id en dos tenants: aborta sin borrar filas.
	_, err = m.Goose.UpTo(ctx, kmsKeysTenantPKVersion)
	require.NoError(t, err)
	insertKey("tenant-b", "key-1")

	_, err = m.Goose.DownTo(ctx, beforeKMSKeysTenantPKVersion)
	require.ErrorContains(t, err, "key_id repetidos entre tenants")
	current, err := m.Goose.GetDBVersion(ctx)
	require.NoError(t, err)
	require.Equal(t, kmsKeysTenantPKVersion, current)
	require.Equal(t, migrated, constraints())
	require.Equal(t, int64(3), countRows())
}
