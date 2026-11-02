package postgres

import (
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	postgrestest "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestKMSSelectExistsByAliasTenantIsolation(t *testing.T) {
	logger := helpers.SetupLogger(config.Info, "test", "kms-repo-tenant-isolation")

	_, suite := postgrestest.BeforeSuite([]string{"kms"}, false)
	defer suite.AfterSuite()
	suite.BeforeEach()

	db := suite.DB["kms"]

	migrator := NewMigrator(logger, db)
	migrator.MigrateToLatest()

	repo, err := NewKMSPostgresRepository(logger, db)
	require.NoError(t, err)

	tenantA := deviceGroupsTenantContext("00000000-0000-0000-0000-0000000000a1")
	tenantB := deviceGroupsTenantContext("00000000-0000-0000-0000-0000000000b2")

	key := &models.Key{
		KeyID:      "kms-key-tenant-a",
		Name:       "tenant-a-key",
		Aliases:    []string{"shared-alias"},
		EngineID:   "filesystem-1",
		Algorithm:  "RSA",
		Size:       4096,
		CreationTS: time.Now(),
		Tags:       []string{},
		Metadata:   map[string]any{},
	}

	_, err = repo.Insert(tenantA, key)
	require.NoError(t, err)

	found, got, err := repo.SelectExistsByAlias(tenantA, "shared-alias")
	require.NoError(t, err)
	assert.True(t, found)
	require.NotNil(t, got)
	assert.Equal(t, "kms-key-tenant-a", got.KeyID)

	found, got, err = repo.SelectExistsByAlias(tenantB, "shared-alias")
	require.NoError(t, err)
	assert.False(t, found)
	assert.Nil(t, got)
}

func TestKMSKeyIdentityTenantIsolation(t *testing.T) {
	logger := helpers.SetupLogger(config.Info, "test", "kms-repo-key-identity-tenant-isolation")

	_, suite := postgrestest.BeforeSuite([]string{"kms"}, false)
	defer suite.AfterSuite()
	suite.BeforeEach()

	db := suite.DB["kms"]
	NewMigrator(logger, db).MigrateToLatest()

	repo, err := NewKMSPostgresRepository(logger, db)
	require.NoError(t, err)

	tenantA := deviceGroupsTenantContext("00000000-0000-0000-0000-0000000000a1")
	tenantB := deviceGroupsTenantContext("00000000-0000-0000-0000-0000000000b2")

	newKey := func(name string) *models.Key {
		return &models.Key{
			KeyID:      "shared-key",
			EngineID:   "filesystem-1",
			Name:       name,
			Algorithm:  "RSA",
			Size:       4096,
			PublicKey:  "pub",
			CreationTS: time.Now(),
			Aliases:    []string{},
			Tags:       []string{},
			Metadata:   map[string]any{},
		}
	}

	_, err = repo.Insert(tenantA, newKey("tenant-a-key"))
	require.NoError(t, err)

	t.Run("another tenant cannot find the key", func(t *testing.T) {
		exists, _, err := repo.SelectExistsByKeyID(tenantB, "shared-key", "filesystem-1")
		require.NoError(t, err)
		assert.False(t, exists)

		keys, err := repo.SelectByKeyID(tenantB, "shared-key")
		require.NoError(t, err)
		assert.Empty(t, keys)
	})

	t.Run("another tenant cannot update or delete the key", func(t *testing.T) {
		_, err := repo.Update(tenantB, newKey("hijacked"))
		assert.ErrorIs(t, err, gorm.ErrRecordNotFound)

		err = repo.Delete(tenantB, "shared-key", "filesystem-1")
		assert.ErrorIs(t, err, gorm.ErrRecordNotFound)

		exists, key, err := repo.SelectExistsByKeyID(tenantA, "shared-key", "filesystem-1")
		require.NoError(t, err)
		require.True(t, exists)
		assert.Equal(t, "tenant-a-key", key.Name)
	})

	t.Run("each tenant keeps its own copy of the same key", func(t *testing.T) {
		_, err := repo.Insert(tenantB, newKey("tenant-b-key"))
		require.NoError(t, err)

		keysA, err := repo.SelectByKeyID(tenantA, "shared-key")
		require.NoError(t, err)
		require.Len(t, keysA, 1)
		assert.Equal(t, "tenant-a-key", keysA[0].Name)

		keysB, err := repo.SelectByKeyID(tenantB, "shared-key")
		require.NoError(t, err)
		require.Len(t, keysB, 1)
		assert.Equal(t, "tenant-b-key", keysB[0].Name)
	})

	t.Run("an update only touches the key of its own tenant", func(t *testing.T) {
		_, err := repo.Update(tenantA, newKey("renamed"))
		require.NoError(t, err)

		_, keyA, err := repo.SelectExistsByKeyID(tenantA, "shared-key", "filesystem-1")
		require.NoError(t, err)
		assert.Equal(t, "renamed", keyA.Name)

		_, keyB, err := repo.SelectExistsByKeyID(tenantB, "shared-key", "filesystem-1")
		require.NoError(t, err)
		assert.Equal(t, "tenant-b-key", keyB.Name)
	})
}
