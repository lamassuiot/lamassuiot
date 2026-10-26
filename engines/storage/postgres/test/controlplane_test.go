package postgrestest

import (
	"context"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	postgres "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestControlPlaneMembershipStore(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgres.CONTROLPLANE_SCHEMA}, false)
	defer suite.AfterSuite()

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Test")
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.CONTROLPLANE_SCHEMA))

	db := suite.DB[postgres.CONTROLPLANE_SCHEMA]
	store := postgres.NewControlPlaneMembershipRepository(db)
	ctx := context.Background()

	require.NoError(t, db.Exec(`INSERT INTO organizations (id, name) VALUES ('org-b', 'Org B')`).Error)
	require.NoError(t, db.Exec(`INSERT INTO tenants (id, organization_id, installation_id, name, status, isolation_mode) VALUES
		('tenant-active', 'org-b', 'default', 'Active', 'ACTIVE', 'POOLED'),
		('tenant-suspended', 'org-b', 'default', 'Suspended', 'SUSPENDED', 'POOLED')`).Error)
	require.NoError(t, db.Exec(`INSERT INTO tenants (id, organization_id, installation_id, name, status, isolation_mode, deleted_at) VALUES
		('tenant-deleted', 'org-b', 'default', 'Deleted', 'DELETED', 'POOLED', now())`).Error)
	require.NoError(t, db.Exec(`INSERT INTO identities (issuer, subject) VALUES
		('https://issuer.example', 'subject-1'),
		('https://issuer.example', 'subject-2')`).Error)
	require.NoError(t, db.Exec(`INSERT INTO memberships (id, organization_id, tenant_id, identity_issuer, identity_subject, role, status) VALUES
		('membership-active', 'org-b', 'tenant-active', 'https://issuer.example', 'subject-1', 'operator', 'ACTIVE'),
		('membership-suspended', 'org-b', 'tenant-active', 'https://issuer.example', 'subject-2', 'viewer', 'SUSPENDED'),
		('membership-suspended-tenant', 'org-b', 'tenant-suspended', 'https://issuer.example', 'subject-1', 'operator', 'ACTIVE')`).Error)

	t.Run("finds an active membership in an active tenant", func(t *testing.T) {
		membership, tenant, err := store.FindActiveMembership(ctx, "https://issuer.example", "subject-1", "tenant-active")
		require.NoError(t, err)
		assert.Equal(t, "membership-active", membership.ID)
		assert.Equal(t, models.RoleOperator, membership.Role)
		assert.Equal(t, "tenant-active", tenant.ID)
		assert.Equal(t, "org-b", tenant.OrganizationID)
	})

	t.Run("rejects a suspended membership", func(t *testing.T) {
		_, _, err := store.FindActiveMembership(ctx, "https://issuer.example", "subject-2", "tenant-active")
		assert.ErrorIs(t, err, postgres.ErrActiveMembershipNotFound)
	})

	t.Run("rejects a tenant without membership", func(t *testing.T) {
		_, _, err := store.FindActiveMembership(ctx, "https://issuer.example", "subject-1", models.DefaultTenantID)
		assert.ErrorIs(t, err, postgres.ErrActiveMembershipNotFound)
	})

	t.Run("rejects an active membership in a suspended tenant", func(t *testing.T) {
		_, _, err := store.FindActiveMembership(ctx, "https://issuer.example", "subject-1", "tenant-suspended")
		assert.ErrorIs(t, err, postgres.ErrActiveMembershipNotFound)
	})

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
			assert.ErrorIs(t, err, postgres.ErrActiveMembershipNotFound, tenantID)
		}
	})
}
