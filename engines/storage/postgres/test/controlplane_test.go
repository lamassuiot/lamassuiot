package postgrestest

import (
	"context"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	postgres "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestControlPlaneTenantStore(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgres.CONTROLPLANE_SCHEMA}, false)
	defer suite.AfterSuite()

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Test")
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.CONTROLPLANE_SCHEMA))

	db := suite.DB[postgres.CONTROLPLANE_SCHEMA]
	store := postgres.NewControlPlaneTenantRepository(db)
	ctx := context.Background()

	require.NoError(t, db.Exec(`INSERT INTO organizations (id, name) VALUES ('org-b', 'Org B')`).Error)
	require.NoError(t, db.Exec(`INSERT INTO tenants (id, organization_id, installation_id, name, status, isolation_mode) VALUES
		('tenant-active', 'org-b', 'default', 'Active', 'ACTIVE', 'POOLED'),
		('tenant-suspended', 'org-b', 'default', 'Suspended', 'SUSPENDED', 'POOLED')`).Error)
	require.NoError(t, db.Exec(`INSERT INTO tenants (id, organization_id, installation_id, name, status, isolation_mode, deleted_at) VALUES
		('tenant-deleted', 'org-b', 'default', 'Deleted', 'DELETED', 'POOLED', now())`).Error)

	t.Run("lists only active tenants", func(t *testing.T) {
		tenants, err := store.ListActiveTenants(ctx)
		require.NoError(t, err)

		ids := []string{}
		for _, tenant := range tenants {
			ids = append(ids, tenant.ID)
		}
		assert.ElementsMatch(t, []string{models.DefaultTenantID, "tenant-active"}, ids)
	})

	t.Run("gets only active tenants", func(t *testing.T) {
		tenant, err := store.GetActiveTenant(ctx, "tenant-active")
		require.NoError(t, err)
		assert.Equal(t, "tenant-active", tenant.ID)

		for _, tenantID := range []string{"tenant-suspended", "tenant-deleted", "tenant-unknown"} {
			_, err := store.GetActiveTenant(ctx, tenantID)
			assert.ErrorIs(t, err, errs.ErrTenantNotFound, tenantID)
		}
	})
}
