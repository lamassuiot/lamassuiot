package postgrestest

import (
	"fmt"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	postgresstorage "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// outboxRLSDatabases son todas las bases que crean la tabla event_outbox.
var outboxRLSDatabases = []string{
	postgresstorage.CA_DB_NAME,
	postgresstorage.DEVICE_DB_NAME,
	postgresstorage.DMS_DB_NAME,
	postgresstorage.ALERTS_DB_NAME,
	postgresstorage.VA_DB_NAME,
	postgresstorage.KMS_DB_NAME,
	postgresstorage.CONTROLPLANE_DB_NAME,
}

// TestEventOutboxTenantRLSPreventsCrossTenantAccess comprueba que, con el rol
// lamassu_app, event_outbox aplica el mismo aislamiento por tenant que el resto
// de tablas por tenant (003, referencia cruzada 006 T3).
func TestEventOutboxTenantRLSPreventsCrossTenantAccess(t *testing.T) {
	cfg, suite := BeforeSuite(outboxRLSDatabases, false)
	defer suite.AfterSuite()

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "outbox RLS test")
	for _, dbName := range outboxRLSDatabases {
		require.NoError(t, postgresstorage.MigrateDatabase(logger, cfg, dbName))
	}
	require.NoError(t, suite.DB[postgresstorage.CONTROLPLANE_DB_NAME].Exec("ALTER ROLE lamassu_app PASSWORD 'outbox-rls-test'").Error)

	for _, dbName := range outboxRLSDatabases {
		t.Run(dbName, func(t *testing.T) {
			adminDB := suite.DB[dbName]
			appDB, err := gorm.Open(postgres.Open(fmt.Sprintf(
				"host=%s port=%d user=lamassu_app dbname=%s password=outbox-rls-test sslmode=disable",
				cfg.Hostname, cfg.Port, dbName,
			)), &gorm.Config{})
			require.NoError(t, err)

			require.NoError(t, adminDB.Create(outboxTestRecord("event-a", "tenant-a")).Error)
			require.NoError(t, adminDB.Create(outboxTestRecord("event-b", "tenant-b")).Error)

			var unscopedCount int64
			require.NoError(t, appDB.Raw("SELECT count(*) FROM event_outbox").Scan(&unscopedCount).Error)
			require.Zero(t, unscopedCount, "sin tenant fijado no se ve ninguna fila")

			countEvents := func(tenantID string) int64 {
				var count int64
				require.NoError(t, postgresstorage.WithTenantTransaction(testTenantContext(tenantID), appDB, func(tx *gorm.DB) error {
					return tx.Raw("SELECT count(*) FROM event_outbox").Scan(&count).Error
				}))
				return count
			}
			require.Equal(t, int64(1), countEvents("tenant-a"))
			require.Equal(t, int64(1), countEvents("tenant-b"))

			ctxA := testTenantContext("tenant-a")
			err = postgresstorage.WithTenantTransaction(ctxA, appDB, func(tx *gorm.DB) error {
				return tx.Create(outboxTestRecord("event-cross", "tenant-b")).Error
			})
			require.Error(t, err, "no se inserta una fila de otro tenant")

			err = postgresstorage.WithTenantTransaction(ctxA, appDB, func(tx *gorm.DB) error {
				result := tx.Exec("UPDATE event_outbox SET status = ? WHERE event_id = ?", "FAILED", "event-b")
				require.NoError(t, result.Error)
				require.Zero(t, result.RowsAffected)
				return nil
			})
			require.NoError(t, err)

			err = postgresstorage.WithTenantTransaction(ctxA, appDB, func(tx *gorm.DB) error {
				return tx.Exec("UPDATE event_outbox SET tenant_id = ? WHERE event_id = ?", "tenant-b", "event-a").Error
			})
			require.Error(t, err, "no se mueve una fila a otro tenant")

			err = postgresstorage.WithTenantTransaction(ctxA, appDB, func(tx *gorm.DB) error {
				result := tx.Exec("DELETE FROM event_outbox WHERE event_id = ?", "event-b")
				require.NoError(t, result.Error)
				require.Zero(t, result.RowsAffected)
				return nil
			})
			require.NoError(t, err)

			// El repositorio del outbox funciona con el rol sin privilegios.
			store := postgresstorage.NewEventOutboxRepository(appDB)
			require.NoError(t, store.Enqueue(ctxA, outboxTestRecord("event-a-2", "tenant-a")))
			claimed, err := store.ClaimPending(ctxA, 10)
			require.NoError(t, err)
			require.Len(t, claimed, 2)
			for _, record := range claimed {
				require.Equal(t, "tenant-a", record.TenantID)
			}
			require.NoError(t, store.MarkPublished(ctxA, "event-a"))
			require.NoError(t, store.ScheduleRetry(ctxA, "event-a-2", "broker unavailable", time.Now().UTC()))
			require.NoError(t, store.MarkFailed(ctxA, "event-a-2", "broker unavailable"))
			require.ErrorIs(t, store.MarkPublished(ctxA, "event-b"), gorm.ErrRecordNotFound)

			var tenantBRecord models.EventOutboxRecord
			require.NoError(t, adminDB.Where("event_id = ?", "event-b").First(&tenantBRecord).Error)
			require.Equal(t, models.EventOutboxPending, tenantBRecord.Status)
			require.Zero(t, tenantBRecord.Attempts)
		})
	}
}
