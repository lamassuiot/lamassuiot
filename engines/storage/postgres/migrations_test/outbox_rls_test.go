package migrationstest

import (
	"context"
	"fmt"
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
	postgres_test "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/test"
	"github.com/stretchr/testify/require"
	postgresDriver "gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const (
	eventOutboxRLSVersion       = int64(20260928140000)
	beforeEventOutboxRLSVersion = eventOutboxRLSVersion - 1
)

// TestEventOutboxRLSMigration comprueba que la migración activa y fuerza RLS en
// event_outbox con la política de tenant en todas las bases, y que el down la
// retira (003, referencia cruzada 006 T3). En las bases de servicio la migración
// también concede los permisos a lamassu_app; en controlplane ya los concedía
// 20260928130000_grant_lamassu_app y el down no los toca.
func TestEventOutboxRLSMigration(t *testing.T) {
	dbNames := []string{
		postgres.CA_DB_NAME,
		postgres.DEVICE_DB_NAME,
		postgres.DMS_DB_NAME,
		postgres.ALERTS_DB_NAME,
		postgres.VA_DB_NAME,
		postgres.KMS_DB_NAME,
		postgres.CONTROLPLANE_DB_NAME,
	}
	dbs := map[string]string{}
	for _, dbName := range dbNames {
		dbs[dbName] = ""
	}
	cleanup, cfg, err := postgres_test.RunPostgresDocker(dbs, false)
	require.NoError(t, err)
	defer cleanup()

	logger := helpers.SetupLogger(config.Info, "test", "test")
	ctx := context.Background()

	for _, dbName := range dbNames {
		t.Run(dbName, func(t *testing.T) {
			con, err := gorm.Open(postgresDriver.New(postgresDriver.Config{
				DSN: fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=disable",
					cfg.Hostname, cfg.Username, cfg.Password, dbName, cfg.Port),
				PreferSimpleProtocol: true,
			}), &gorm.Config{Logger: postgres.NewGormLogger(logger)})
			require.NoError(t, err)

			type rlsState struct {
				Enabled bool
				Forced  bool
				Policy  bool
			}
			loadState := func() rlsState {
				var state rlsState
				require.NoError(t, con.Raw(`SELECT c.relrowsecurity AS enabled, c.relforcerowsecurity AS forced,
					EXISTS (SELECT 1 FROM pg_policies p WHERE p.tablename = 'event_outbox'
						AND p.policyname = 'event_outbox_tenant_isolation'
						AND p.roles = '{lamassu_app}' AND p.cmd = 'ALL'
						AND p.qual LIKE '%app.tenant_id%' AND p.with_check LIKE '%app.tenant_id%') AS policy
					FROM pg_class c WHERE c.relname = 'event_outbox' AND c.relkind = 'r'`).Scan(&state).Error)
				return state
			}
			hasAllPrivileges := func() bool {
				var granted bool
				require.NoError(t, con.Raw(`SELECT has_table_privilege('lamassu_app', 'event_outbox', 'SELECT')
					AND has_table_privilege('lamassu_app', 'event_outbox', 'INSERT')
					AND has_table_privilege('lamassu_app', 'event_outbox', 'UPDATE')
					AND has_table_privilege('lamassu_app', 'event_outbox', 'DELETE')`).Scan(&granted).Error)
				return granted
			}
			grantedBefore := dbName == postgres.CONTROLPLANE_DB_NAME

			m := postgres.NewMigrator(logger, con)
			_, err = m.Goose.UpTo(ctx, beforeEventOutboxRLSVersion)
			require.NoError(t, err)
			require.Equal(t, rlsState{}, loadState(), "sin RLS antes de la migración")
			require.Equal(t, grantedBefore, hasAllPrivileges())

			_, err = m.Goose.UpTo(ctx, eventOutboxRLSVersion)
			require.NoError(t, err)
			current, err := m.Goose.GetDBVersion(ctx)
			require.NoError(t, err)
			require.Equal(t, eventOutboxRLSVersion, current)
			require.Equal(t, rlsState{Enabled: true, Forced: true, Policy: true}, loadState())
			require.True(t, hasAllPrivileges(), "lamassu_app opera event_outbox tras el up")

			_, err = m.Goose.DownTo(ctx, beforeEventOutboxRLSVersion)
			require.NoError(t, err)
			current, err = m.Goose.GetDBVersion(ctx)
			require.NoError(t, err)
			require.Less(t, current, eventOutboxRLSVersion)
			require.Equal(t, rlsState{}, loadState(), "el down retira RLS y política")
			require.Equal(t, grantedBefore, hasAllPrivileges(), "el down restaura los permisos previos")
		})
	}
}
