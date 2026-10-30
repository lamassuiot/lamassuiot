package postgrestest

import (
	"context"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	postgres "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeviceManagerStoresTenantIsolation(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgres.DEVICE_SCHEMA}, false)
	defer suite.AfterSuite()

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Test")
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.DEVICE_SCHEMA))

	devices, err := postgres.NewDeviceManagerRepository(logger, suite.DB[postgres.DEVICE_SCHEMA])
	require.NoError(t, err)
	events := devices.DeviceEvents()

	ctxA := tenantTestContext("tenant-a", models.TenantActive)
	ctxB := tenantTestContext("tenant-b", models.TenantActive)

	newDevice := func(id string) *models.Device {
		return &models.Device{
			ID:                id,
			Status:            models.DeviceActive,
			CreationTimestamp: time.Now().UTC().Truncate(time.Second),
			Tags:              []string{},
			Metadata:          map[string]any{},
			ExtraSlots:        map[string]*models.Slot[any]{},
		}
	}

	newEvent := func(id string, deviceID string) *models.DeviceEventRecord {
		return &models.DeviceEventRecord{
			ID:               id,
			DeviceID:         deviceID,
			EventTS:          time.Now().UTC().Truncate(time.Second),
			EventType:        "CREATED",
			StructuredFields: map[string]any{},
		}
	}

	eventsOf := func(t *testing.T, ctx context.Context, deviceID string) []string {
		ids := []string{}
		_, err := events.SelectByDeviceID(ctx, storage.StorageListRequest[models.DeviceEventRecord]{
			ExhaustiveRun: true,
			ApplyFunc: func(event models.DeviceEventRecord) {
				ids = append(ids, event.ID)
			},
		}, deviceID)
		require.NoError(t, err)
		return ids
	}

	t.Run("insert takes the tenant from the context", func(t *testing.T) {
		device := newDevice("device-a")
		device.TenantID = "tenant-b"
		inserted, err := devices.Insert(ctxA, device)
		require.NoError(t, err)
		assert.Equal(t, "tenant-a", inserted.TenantID)

		event, err := events.Insert(ctxA, newEvent("event-a", "device-a"))
		require.NoError(t, err)
		assert.Equal(t, "tenant-a", event.TenantID)
	})

	t.Run("another tenant cannot read the device", func(t *testing.T) {
		exists, _, err := devices.SelectExists(ctxA, "device-a")
		require.NoError(t, err)
		assert.True(t, exists)

		exists, _, err = devices.SelectExists(ctxB, "device-a")
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("another tenant cannot read its events", func(t *testing.T) {
		assert.Equal(t, []string{"event-a"}, eventsOf(t, ctxA, "device-a"))
		assert.Empty(t, eventsOf(t, ctxB, "device-a"))
	})

	t.Run("another tenant cannot attach events to the device", func(t *testing.T) {
		_, err := events.Insert(ctxB, newEvent("event-b", "device-a"))
		assert.Error(t, err)
	})

	t.Run("another tenant cannot delete its events", func(t *testing.T) {
		require.NoError(t, events.DeleteByDeviceID(ctxB, "device-a"))
		assert.Equal(t, []string{"event-a"}, eventsOf(t, ctxA, "device-a"))
	})

	t.Run("the owner tenant deletes its events", func(t *testing.T) {
		require.NoError(t, events.DeleteByDeviceID(ctxA, "device-a"))
		assert.Empty(t, eventsOf(t, ctxA, "device-a"))
	})
}
