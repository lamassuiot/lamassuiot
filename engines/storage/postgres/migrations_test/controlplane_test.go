package migrationstest

import (
	"context"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
	"github.com/stretchr/testify/require"
)

var ControlPlaneDBName = "controlplane"

const (
	controlPlaneTenantManagementVersion = int64(20260925120000)
	controlPlaneSimplifyLifecycle       = int64(20260928120000)
	controlPlaneGrantLamassuApp         = int64(20260928130000)
)

// controlPlaneAppTables son las tablas de controlplane que usa el rol de
// aplicación sin privilegios (Tenant Manager, membresías, selectores, outbox).
var controlPlaneAppTables = []string{
	"organizations",
	"tenants",
	"identities",
	"memberships",
	"invitations",
	"dedicated_crypto_selectors",
	"event_outbox",
}

// TestControlPlaneSimplifyTenantLifecycleMigration checks that the tenant
// lifecycle migration retires PROVISIONING and DEPROVISIONING (005 T10.1).
func TestControlPlaneSimplifyTenantLifecycleMigration(t *testing.T) {
	logger := helpers.SetupLogger(config.Info, "test", "test")
	cleanup, con := RunDB(t, logger, ControlPlaneDBName)
	defer cleanup()

	ctx := context.Background()
	m := postgres.NewMigrator(logger, con)
	_, err := m.Goose.UpTo(ctx, controlPlaneTenantManagementVersion)
	require.NoError(t, err)

	require.NoError(t, con.Exec(`INSERT INTO organizations (id, name) VALUES ('org-a', 'Org A')`).Error)
	require.NoError(t, con.Exec(`INSERT INTO tenants (id, organization_id, name, status, isolation_mode) VALUES
		('t-provisioning', 'org-a', 'provisioning', 'PROVISIONING', 'POOLED'),
		('t-deprovisioning', 'org-a', 'deprovisioning', 'DEPROVISIONING', 'POOLED'),
		('t-active', 'org-a', 'active', 'ACTIVE', 'POOLED')`).Error)
	before := time.Now()

	_, err = m.Goose.UpTo(ctx, controlPlaneSimplifyLifecycle)
	require.NoError(t, err)
	current, err := m.Goose.GetDBVersion(ctx)
	require.NoError(t, err)
	require.Equal(t, controlPlaneSimplifyLifecycle, current)

	type row struct {
		ID        string
		Status    string
		DeletedAt *time.Time
	}
	load := func(id string) row {
		var r row
		require.NoError(t, con.Raw(`SELECT id, status, deleted_at FROM tenants WHERE id = ?`, id).Scan(&r).Error)
		return r
	}

	provisioning := load("t-provisioning")
	require.Equal(t, "SUSPENDED", provisioning.Status, "PROVISIONING tenants become SUSPENDED")
	require.Nil(t, provisioning.DeletedAt)

	deprovisioning := load("t-deprovisioning")
	require.Equal(t, "DELETED", deprovisioning.Status, "DEPROVISIONING tenants become DELETED")
	require.NotNil(t, deprovisioning.DeletedAt)
	require.WithinDuration(t, before, *deprovisioning.DeletedAt, time.Minute)

	active := load("t-active")
	require.Equal(t, "ACTIVE", active.Status)
	require.Nil(t, active.DeletedAt)

	for _, retired := range []string{"PROVISIONING", "DEPROVISIONING"} {
		err := con.Exec(`INSERT INTO tenants (id, organization_id, name, status, isolation_mode) VALUES (?, 'org-a', ?, ?, 'POOLED')`,
			"t-new-"+retired, "new-"+retired, retired).Error
		require.Error(t, err, "%s is rejected by tenants_status_check", retired)
	}

	_, err = m.Goose.DownTo(ctx, controlPlaneTenantManagementVersion)
	require.NoError(t, err)
	current, err = m.Goose.GetDBVersion(ctx)
	require.NoError(t, err)
	require.Equal(t, controlPlaneTenantManagementVersion, current)

	require.Equal(t, "SUSPENDED", load("t-provisioning").Status, "down keeps converted rows")
	require.Equal(t, "DELETED", load("t-deprovisioning").Status, "down keeps converted rows")
	for _, restored := range []string{"PROVISIONING", "DEPROVISIONING"} {
		require.NoError(t, con.Exec(`INSERT INTO tenants (id, organization_id, name, status, isolation_mode) VALUES (?, 'org-a', ?, ?, 'POOLED')`,
			"t-down-"+restored, "down-"+restored, restored).Error, "down restores the six-state check")
	}
}

// TestControlPlaneGrantLamassuAppMigration comprueba que lamassu_app recibe
// SELECT/INSERT/UPDATE/DELETE sobre las tablas de controlplane tras up y los
// pierde tras down (005 T10.1).
func TestControlPlaneGrantLamassuAppMigration(t *testing.T) {
	logger := helpers.SetupLogger(config.Info, "test", "test")
	cleanup, con := RunDB(t, logger, ControlPlaneDBName)
	defer cleanup()

	ctx := context.Background()
	m := postgres.NewMigrator(logger, con)
	_, err := m.Goose.UpTo(ctx, controlPlaneSimplifyLifecycle)
	require.NoError(t, err)

	privileges := []string{"SELECT", "INSERT", "UPDATE", "DELETE"}
	roleExists := func() bool {
		var exists bool
		require.NoError(t, con.Raw(`SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'lamassu_app')`).Scan(&exists).Error)
		return exists
	}
	hasPrivilege := func(table, privilege string) bool {
		var granted bool
		require.NoError(t, con.Raw(`SELECT has_table_privilege('lamassu_app', ?, ?)`, table, privilege).Scan(&granted).Error)
		return granted
	}

	if roleExists() {
		for _, table := range controlPlaneAppTables {
			for _, privilege := range privileges {
				require.False(t, hasPrivilege(table, privilege), "lamassu_app has no %s on %s before the migration", privilege, table)
			}
		}
	}

	_, err = m.Goose.UpTo(ctx, controlPlaneGrantLamassuApp)
	require.NoError(t, err)
	current, err := m.Goose.GetDBVersion(ctx)
	require.NoError(t, err)
	require.Equal(t, controlPlaneGrantLamassuApp, current)

	require.True(t, roleExists(), "the migration creates lamassu_app when missing")
	for _, table := range controlPlaneAppTables {
		for _, privilege := range privileges {
			require.True(t, hasPrivilege(table, privilege), "lamassu_app has %s on %s after up", privilege, table)
		}
	}

	_, err = m.Goose.DownTo(ctx, controlPlaneSimplifyLifecycle)
	require.NoError(t, err)
	current, err = m.Goose.GetDBVersion(ctx)
	require.NoError(t, err)
	require.Equal(t, controlPlaneSimplifyLifecycle, current)

	for _, table := range controlPlaneAppTables {
		for _, privilege := range privileges {
			require.False(t, hasPrivilege(table, privilege), "lamassu_app loses %s on %s after down", privilege, table)
		}
	}
}
