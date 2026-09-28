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
)

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
