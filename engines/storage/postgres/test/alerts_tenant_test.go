package postgrestest

import (
	"context"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	postgres "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestAlertsStoresTenantIsolation(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgres.ALERTS_SCHEMA}, false)
	defer suite.AfterSuite()

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Test")
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.ALERTS_SCHEMA))

	subscriptions, err := postgres.NewSubscriptionsPostgresRepository(logger, suite.DB[postgres.ALERTS_SCHEMA])
	require.NoError(t, err)
	events, err := postgres.NewEventsPostgresRepository(logger, suite.DB[postgres.ALERTS_SCHEMA])
	require.NoError(t, err)

	ctxA := tenantTestContext("tenant-a", models.TenantActive)
	ctxB := tenantTestContext("tenant-b", models.TenantActive)

	subscriptionsOfUser := func(t *testing.T, ctx context.Context, userID string) []string {
		ids := []string{}
		_, err := subscriptions.GetSubscriptions(ctx, userID, true, func(sub models.Subscription) {
			ids = append(ids, sub.ID)
		}, nil, nil)
		require.NoError(t, err)
		return ids
	}

	newEvent := func(totalSeen int) *models.AlertLatestEvent {
		event := cloudevents.NewEvent()
		event.SetID("event-test")
		event.SetSource("test")
		event.SetType("certificate.expired")
		return &models.AlertLatestEvent{
			TenantID:  "tenant-b",
			EventType: models.EventType("certificate.expired"),
			Event:     event,
			LastSeen:  time.Now().UTC().Truncate(time.Second),
			TotalSeen: totalSeen,
		}
	}

	t.Run("subscribe takes the tenant from the context", func(t *testing.T) {
		sub, err := subscriptions.Subscribe(ctxA, &models.Subscription{
			ID:               "sub-a",
			TenantID:         "tenant-b",
			UserID:           "user-1",
			EventType:        models.EventType("certificate.expired"),
			SubscriptionDate: time.Now().UTC().Truncate(time.Second),
			Conditions:       []models.SubscriptionCondition{},
		})
		require.NoError(t, err)
		assert.Equal(t, "tenant-a", sub.TenantID)
	})

	t.Run("another tenant cannot list it", func(t *testing.T) {
		assert.Equal(t, []string{"sub-a"}, subscriptionsOfUser(t, ctxA, "user-1"))
		assert.Empty(t, subscriptionsOfUser(t, ctxB, "user-1"))

		byTypeB := []string{}
		_, err := subscriptions.GetSubscriptionsByEventType(ctxB, "certificate.expired", true, func(sub models.Subscription) {
			byTypeB = append(byTypeB, sub.ID)
		}, nil, nil)
		require.NoError(t, err)
		assert.Empty(t, byTypeB)
	})

	t.Run("another tenant cannot unsubscribe it", func(t *testing.T) {
		err := subscriptions.Unsubscribe(ctxB, "sub-a")
		assert.ErrorIs(t, err, gorm.ErrRecordNotFound)

		assert.Equal(t, []string{"sub-a"}, subscriptionsOfUser(t, ctxA, "user-1"))
	})

	t.Run("each tenant keeps its own latest event", func(t *testing.T) {
		eventA, err := events.InsertUpdateEvent(ctxA, newEvent(1))
		require.NoError(t, err)
		assert.Equal(t, "tenant-a", eventA.TenantID)

		_, err = events.InsertUpdateEvent(ctxB, newEvent(5))
		require.NoError(t, err)

		_, err = events.InsertUpdateEvent(ctxA, newEvent(2))
		require.NoError(t, err)

		exists, latestA, err := events.GetLatestEventByEventType(ctxA, models.EventType("certificate.expired"))
		require.NoError(t, err)
		require.True(t, exists)
		assert.Equal(t, 2, latestA.TotalSeen)

		exists, latestB, err := events.GetLatestEventByEventType(ctxB, models.EventType("certificate.expired"))
		require.NoError(t, err)
		require.True(t, exists)
		assert.Equal(t, 5, latestB.TotalSeen)
	})

	t.Run("latest events are listed per tenant", func(t *testing.T) {
		tenants := []string{}
		_, err := events.GetLatestEvents(ctxB, storage.StorageListRequest[models.AlertLatestEvent]{
			ExhaustiveRun: true,
			ApplyFunc: func(event models.AlertLatestEvent) {
				tenants = append(tenants, event.TenantID)
			},
		})
		require.NoError(t, err)
		assert.Equal(t, []string{"tenant-b"}, tenants)
	})
}
