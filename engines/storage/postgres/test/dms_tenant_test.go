package postgrestest

import (
	"context"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	postgres "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func tenantTestContext(tenantID string, status models.TenantStatus) context.Context {
	return core.WithTenantContext(context.Background(), core.TenantContext{
		OrganizationID: "org-test",
		TenantID:       tenantID,
		ActorID:        "actor-test",
		ActorType:      "system",
		CorrelationID:  "corr-test",
		Source:         "test",
		TenantStatus:   status,
		Validated:      true,
	})
}

func TestDMSStoreTenantIsolation(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgres.DMS_SCHEMA}, false)
	defer suite.AfterSuite()

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Test")
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.DMS_SCHEMA))

	store, err := postgres.NewDMSManagerRepository(logger, suite.DB[postgres.DMS_SCHEMA])
	require.NoError(t, err)

	ctxA := tenantTestContext("tenant-a", models.TenantActive)
	ctxB := tenantTestContext("tenant-b", models.TenantActive)

	newDMS := func(id string, tenantID string) *models.DMS {
		return &models.DMS{
			ID:           id,
			TenantID:     tenantID,
			Name:         "DMS " + id,
			Metadata:     map[string]any{},
			CreationDate: time.Now().UTC().Truncate(time.Second),
		}
	}

	t.Run("insert takes the tenant from the context", func(t *testing.T) {
		dms, err := store.Insert(ctxA, newDMS("dms-a", "tenant-b"))
		require.NoError(t, err)
		assert.Equal(t, "tenant-a", dms.TenantID)
	})

	t.Run("another tenant cannot read it", func(t *testing.T) {
		exists, _, err := store.SelectExists(ctxA, "dms-a")
		require.NoError(t, err)
		assert.True(t, exists)

		exists, _, err = store.SelectExists(ctxB, "dms-a")
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("counts and lists are scoped to the tenant", func(t *testing.T) {
		countA, err := store.Count(ctxA)
		require.NoError(t, err)
		assert.Equal(t, 1, countA)

		countB, err := store.Count(ctxB)
		require.NoError(t, err)
		assert.Equal(t, 0, countB)

		listed := []string{}
		_, err = store.SelectAll(ctxB, true, func(dms models.DMS) {
			listed = append(listed, dms.ID)
		}, nil, nil)
		require.NoError(t, err)
		assert.Empty(t, listed)
	})

	t.Run("another tenant cannot update it", func(t *testing.T) {
		_, err := store.Update(ctxB, newDMS("dms-a", "tenant-b"))
		assert.ErrorIs(t, err, gorm.ErrRecordNotFound)

		_, dms, err := store.SelectExists(ctxA, "dms-a")
		require.NoError(t, err)
		assert.Equal(t, "DMS dms-a", dms.Name)
		assert.Equal(t, "tenant-a", dms.TenantID)
	})

	t.Run("another tenant cannot delete it", func(t *testing.T) {
		err := store.Delete(ctxB, "dms-a")
		assert.ErrorIs(t, err, gorm.ErrRecordNotFound)

		exists, _, err := store.SelectExists(ctxA, "dms-a")
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("without tenant context uses the default tenant", func(t *testing.T) {
		dms, err := store.Insert(context.Background(), newDMS("dms-default", ""))
		require.NoError(t, err)
		assert.Equal(t, models.DefaultTenantID, dms.TenantID)

		exists, _, err := store.SelectExists(tenantTestContext(models.DefaultTenantID, models.TenantActive), "dms-default")
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("rejects an invalid tenant context", func(t *testing.T) {
		_, err := store.Count(tenantTestContext("tenant-a", models.TenantSuspended))
		assert.ErrorIs(t, err, core.ErrTenantContextInvalid)
	})
}
