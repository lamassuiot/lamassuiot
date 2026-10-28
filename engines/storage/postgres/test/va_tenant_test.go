package postgrestest

import (
	"math/big"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	postgres "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestVAStoreTenantIsolation(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgres.VA_SCHEMA}, false)
	defer suite.AfterSuite()

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Test")
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.VA_SCHEMA))

	store, err := postgres.NewVARepository(logger, suite.DB[postgres.VA_SCHEMA])
	require.NoError(t, err)

	ctxA := tenantTestContext("tenant-a", models.TenantActive)
	ctxB := tenantTestContext("tenant-b", models.TenantActive)

	newRole := func(caSki string, tenantID string, version int64) *models.VARole {
		now := time.Now().UTC().Truncate(time.Second)
		return &models.VARole{
			CASubjectKeyID: caSki,
			TenantID:       tenantID,
			CRLOptions: models.VACRLRole{
				RefreshInterval:    models.TimeDuration(24 * time.Hour),
				Validity:           models.TimeDuration(48 * time.Hour),
				SubjectKeyIDSigner: caSki,
				RegenerateOnRevoke: true,
			},
			LatestCRL: models.LatestCRLMeta{
				Version:    models.BigInt{Int: big.NewInt(version)},
				ValidFrom:  now,
				ValidUntil: now.Add(48 * time.Hour),
			},
		}
	}

	t.Run("insert takes the tenant from the context", func(t *testing.T) {
		role, err := store.Insert(ctxA, newRole("ca-ski-1", "tenant-b", 1))
		require.NoError(t, err)
		assert.Equal(t, "tenant-a", role.TenantID)
	})

	t.Run("another tenant cannot read it", func(t *testing.T) {
		exists, _, err := store.Get(ctxA, "ca-ski-1")
		require.NoError(t, err)
		assert.True(t, exists)

		exists, _, err = store.Get(ctxB, "ca-ski-1")
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("another tenant cannot update it", func(t *testing.T) {
		_, err := store.Update(ctxB, newRole("ca-ski-1", "tenant-b", 9))
		assert.ErrorIs(t, err, gorm.ErrRecordNotFound)

		_, role, err := store.Get(ctxA, "ca-ski-1")
		require.NoError(t, err)
		assert.Equal(t, int64(1), role.LatestCRL.Version.Int64())
		assert.Equal(t, "tenant-a", role.TenantID)
	})

	t.Run("each tenant keeps its own role for the same ca", func(t *testing.T) {
		_, err := store.Insert(ctxB, newRole("ca-ski-1", "", 5))
		require.NoError(t, err)

		_, roleA, err := store.Get(ctxA, "ca-ski-1")
		require.NoError(t, err)
		assert.Equal(t, int64(1), roleA.LatestCRL.Version.Int64())

		_, roleB, err := store.Get(ctxB, "ca-ski-1")
		require.NoError(t, err)
		assert.Equal(t, int64(5), roleB.LatestCRL.Version.Int64())
	})

	t.Run("lists are scoped to the tenant", func(t *testing.T) {
		tenants := []string{}
		_, err := store.GetAll(ctxB, storage.StorageListRequest[models.VARole]{
			ExhaustiveRun: true,
			ApplyFunc: func(role models.VARole) {
				tenants = append(tenants, role.TenantID)
			},
		})
		require.NoError(t, err)
		assert.Equal(t, []string{"tenant-b"}, tenants)
	})
}
