package postgrestest

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	postgresstorage "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestTenantOutboxTransactionIsAtomicAndScoped(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgresstorage.ALERTS_DB_NAME}, false)
	defer suite.AfterSuite()

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "outbox test")
	require.NoError(t, postgresstorage.MigrateDatabase(logger, cfg, postgresstorage.ALERTS_DB_NAME))

	db := suite.DB[postgresstorage.ALERTS_DB_NAME]
	require.NoError(t, db.Exec("CREATE TABLE outbox_domain_mutations (id text PRIMARY KEY, tenant_id text NOT NULL)").Error)

	ctxA := testTenantContext("tenant-a")
	first := outboxTestRecord("event-atomic", "tenant-a")
	require.NoError(t, postgresstorage.WithTenantOutboxTransaction(ctxA, db, first, func(tx *gorm.DB) error {
		return tx.Exec("INSERT INTO outbox_domain_mutations (id, tenant_id) VALUES (?, ?)", "committed", "tenant-a").Error
	}))

	duplicate := outboxTestRecord("event-atomic", "tenant-a")
	require.Error(t, postgresstorage.WithTenantOutboxTransaction(ctxA, db, duplicate, func(tx *gorm.DB) error {
		return tx.Exec("INSERT INTO outbox_domain_mutations (id, tenant_id) VALUES (?, ?)", "rolled-back", "tenant-a").Error
	}))

	var mutationCount int64
	require.NoError(t, db.Table("outbox_domain_mutations").Count(&mutationCount).Error)
	require.EqualValues(t, 1, mutationCount, "failed outbox insert must roll back the domain mutation")

	store := postgresstorage.NewEventOutboxRepository(db)
	require.NoError(t, store.MarkPublished(ctxA, "event-atomic"))
	require.NoError(t, store.Enqueue(ctxA, outboxTestRecord("event-a", "tenant-a")))
	require.NoError(t, store.Enqueue(testTenantContext("tenant-b"), outboxTestRecord("event-b", "tenant-b")))

	require.ErrorIs(t, store.MarkPublished(ctxA, "event-b"), gorm.ErrRecordNotFound)
	retryAt := time.Now().UTC()
	require.ErrorIs(t, store.ScheduleRetry(ctxA, "event-b", "broker unavailable", retryAt), gorm.ErrRecordNotFound)
	require.NoError(t, store.ScheduleRetry(testTenantContext("tenant-b"), "event-b", "broker unavailable", retryAt))

	var tenantBRecord models.EventOutboxRecord
	require.NoError(t, db.Where("event_id = ?", "event-b").First(&tenantBRecord).Error)
	require.Equal(t, models.EventOutboxPending, tenantBRecord.Status, "tenant A must not update tenant B's event")
	require.Equal(t, "broker unavailable", tenantBRecord.LastError)
	require.WithinDuration(t, retryAt, tenantBRecord.AvailableAt, time.Second)

	claimedA, err := store.ClaimPending(ctxA, 10)
	require.NoError(t, err)
	require.Len(t, claimedA, 1)
	require.Equal(t, "event-a", claimedA[0].EventID)
	require.Equal(t, "tenant-a", claimedA[0].TenantID)

	claimedB, err := store.ClaimPending(testTenantContext("tenant-b"), 10)
	require.NoError(t, err)
	require.Len(t, claimedB, 1)
	require.Equal(t, "event-b", claimedB[0].EventID)
	require.Equal(t, "tenant-b", claimedB[0].TenantID)
}

func outboxTestRecord(eventID, tenantID string) *models.EventOutboxRecord {
	return &models.EventOutboxRecord{
		EventID:        eventID,
		TenantID:       tenantID,
		OrganizationID: "organization",
		CorrelationID:  "correlation-" + eventID,
		Type:           "test.created",
		Version:        "1",
		Payload:        json.RawMessage(`{"resource":"test"}`),
		Status:         models.EventOutboxPending,
	}
}
