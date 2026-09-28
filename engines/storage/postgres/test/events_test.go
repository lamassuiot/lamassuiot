package postgrestest

import (
	"fmt"
	"sync"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	postgresstorage "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regresión de la carrera de alerts.events (006 T10): InsertUpdateEvent registra una
// aparición de forma atómica aunque lleguen varios eventos del mismo tipo a la vez.
func TestEventsInsertUpdateIsAtomicUnderConcurrency(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgresstorage.ALERTS_DB_NAME, postgresstorage.CONTROLPLANE_DB_NAME}, false)
	defer suite.AfterSuite()

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Events upsert test")
	const appPassword = "events-upsert-test"
	require.NoError(t, postgresstorage.MigrateDatabase(logger, cfg, postgresstorage.CONTROLPLANE_DB_NAME))
	require.NoError(t, postgresstorage.MigrateDatabase(logger, cfg, postgresstorage.ALERTS_DB_NAME))
	require.NoError(t, suite.DB[postgresstorage.CONTROLPLANE_DB_NAME].Exec("ALTER ROLE lamassu_app PASSWORD '"+appPassword+"'").Error)

	// Como en producción: rol lamassu_app, sujeto a RLS.
	appDB := openTenantAppDB(t, cfg.Hostname, cfg.Port, postgresstorage.ALERTS_DB_NAME, appPassword)
	repo, err := postgresstorage.NewEventsPostgresRepository(logger, appDB)
	require.NoError(t, err)

	type call struct{ tenant, evType string }

	record := func(tenant, evType string, seen time.Time) error {
		ev := cloudevents.NewEvent()
		ev.SetID(fmt.Sprintf("%s-%d", evType, seen.UnixNano()))
		ev.SetSource("test")
		ev.SetType(evType)
		_, err := repo.InsertUpdateEvent(testTenantContext(tenant), &models.AlertLatestEvent{
			TenantID:  tenant,
			EventType: models.EventType(evType),
			Event:     ev,
			LastSeen:  seen,
		})
		return err
	}

	runConcurrently := func(calls []call) []error {
		var wg sync.WaitGroup
		var mu sync.Mutex
		var errs []error
		start := make(chan struct{})
		for _, c := range calls {
			wg.Add(1)
			go func(c call) {
				defer wg.Done()
				<-start
				if err := record(c.tenant, c.evType, time.Now()); err != nil {
					mu.Lock()
					errs = append(errs, err)
					mu.Unlock()
				}
			}(c)
		}
		close(start)
		wg.Wait()
		return errs
	}

	latest := func(tenant, evType string) *models.AlertLatestEvent {
		exists, ev, err := repo.GetLatestEventByEventType(testTenantContext(tenant), models.EventType(evType))
		require.NoError(t, err)
		require.True(t, exists, "tenant %s sin fila para %s", tenant, evType)
		return ev
	}

	t.Run("fila nueva con llamadas concurrentes del mismo tenant y tipo", func(t *testing.T) {
		const n = 20
		for i := 0; i < 10; i++ {
			evType := fmt.Sprintf("race.new.%d", i)
			calls := make([]call, n)
			for j := range calls {
				calls[j] = call{"tenant-a", evType}
			}
			assert.Empty(t, runConcurrently(calls))
			assert.Equal(t, n, latest("tenant-a", evType).TotalSeen)
		}
	})

	t.Run("fila existente con llamadas concurrentes", func(t *testing.T) {
		const n = 20
		require.NoError(t, record("tenant-a", "race.existing", time.Now()))
		calls := make([]call, n)
		for j := range calls {
			calls[j] = call{"tenant-a", "race.existing"}
		}
		assert.Empty(t, runConcurrently(calls))
		assert.Equal(t, n+1, latest("tenant-a", "race.existing").TotalSeen)
	})

	t.Run("mismo tipo en dos tenants deja una fila por tenant", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			evType := fmt.Sprintf("race.cross.%d", i)
			assert.Empty(t, runConcurrently([]call{{"tenant-a", evType}, {"tenant-b", evType}, {"tenant-a", evType}, {"tenant-b", evType}}))
			for _, tenant := range []string{"tenant-a", "tenant-b"} {
				ev := latest(tenant, evType)
				assert.Equal(t, tenant, ev.TenantID)
				assert.Equal(t, 2, ev.TotalSeen)
			}
		}
		// Recuento con el rol administrador (sin RLS): una fila por tenant y tipo.
		var rows []struct {
			TenantID  string
			EventType string
			Count     int
		}
		require.NoError(t, suite.DB[postgresstorage.ALERTS_DB_NAME].Raw(
			"SELECT tenant_id, event_type, COUNT(*) AS count FROM events WHERE event_type LIKE 'race.cross.%' GROUP BY tenant_id, event_type").Scan(&rows).Error)
		assert.Len(t, rows, 20)
		for _, r := range rows {
			assert.Equal(t, 1, r.Count, "tenant %s con %d filas para %s", r.TenantID, r.Count, r.EventType)
		}
	})

	t.Run("un evento más antiguo no retrasa last_seen", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Microsecond)
		require.NoError(t, record("tenant-a", "order.check", now))
		require.NoError(t, record("tenant-a", "order.check", now.Add(-time.Hour)))
		ev := latest("tenant-a", "order.check")
		assert.Equal(t, 2, ev.TotalSeen)
		assert.True(t, ev.LastSeen.Equal(now), "last_seen=%s, esperado %s", ev.LastSeen, now)
	})
}
