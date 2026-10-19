package postgrestest

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeviceExhaustiveRun(t *testing.T) {
	_, suite := BeforeSuite([]string{"devicemanager"}, false)
	defer suite.AfterSuite()

	db := suite.DB["devicemanager"]
	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Test")
	postgres.NewMigrator(logger, db).MigrateToLatest()

	repo, err := postgres.NewDeviceManagerRepository(logger, db)
	require.NoError(t, err)

	const total = 7
	insertDevices := func(t *testing.T) {
		require.NoError(t, suite.BeforeEach())
		for i := range total {
			d := models.Device{
				ID:                fmt.Sprintf("device-%02d", i),
				Status:            models.DeviceActive,
				CreationTimestamp: time.Now(),
				Metadata:          map[string]any{},
				Tags:              []string{},
				Events:            map[time.Time]models.DeviceEvent{},
				ExtraSlots:        map[string]*models.Slot[any]{},
			}
			require.NoError(t, db.Create(&d).Error)
		}
	}
	activeOnly := []resources.FilterOption{{
		Field:           "status",
		FilterOperation: resources.EnumEqual,
		Value:           string(models.DeviceActive),
	}}

	// Rows leaving the filter while iterating (e.g. certificates moved to expired
	// by the crypto monitor) must not shift the following batches
	t.Run("visits every row while rows leave the filter", func(t *testing.T) {
		insertDevices(t)

		seen := map[string]int{}
		_, err := repo.SelectAll(context.Background(), true, func(d models.Device) {
			seen[d.ID]++
			require.NoError(t, db.Model(&models.Device{}).Where("id = ?", d.ID).Update("status", models.DeviceDecommissioned).Error)
		}, &resources.QueryParameters{PageSize: 2, Filters: activeOnly}, nil)
		require.NoError(t, err)

		assert.Len(t, seen, total)
		for id, n := range seen {
			assert.Equal(t, 1, n, "device %s visited %d times", id, n)
		}
	})

	t.Run("batch size equal to the number of rows", func(t *testing.T) {
		insertDevices(t)

		var ids []string
		_, err := repo.SelectAll(context.Background(), true, func(d models.Device) {
			ids = append(ids, d.ID)
		}, &resources.QueryParameters{PageSize: total}, nil)
		require.NoError(t, err)
		assert.Len(t, ids, total)
	})

	t.Run("sorting is rejected", func(t *testing.T) {
		_, err := repo.SelectAll(context.Background(), true, func(models.Device) {}, &resources.QueryParameters{
			PageSize: 2,
			Sort:     resources.SortOptions{SortField: "id", SortMode: resources.SortModeDesc},
		}, nil)
		assert.Error(t, err)
	})
}

// KMS keys have no single-column primary key: the same key_id can live in
// several engines, so batches must advance on (key_id, engine_id).
func TestKMSExhaustiveRun(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgres.KMS_SCHEMA}, false)
	defer suite.AfterSuite()

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Test")
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.KMS_SCHEMA))

	store, err := postgres.NewKMSPostgresRepository(logger, suite.DB[postgres.KMS_SCHEMA])
	require.NoError(t, err)

	ctx := context.Background()
	want := map[string]bool{}
	for _, keyID := range []string{"key-a", "key-b", "key-c"} {
		for _, engineID := range []string{"engine-1", "engine-2", "engine-3"} {
			_, err := store.Insert(ctx, &models.Key{
				KeyID:      keyID,
				EngineID:   engineID,
				Name:       keyID + "@" + engineID,
				Algorithm:  "RSA",
				Size:       2048,
				PublicKey:  "pub",
				CreationTS: time.Now().UTC().Truncate(time.Second),
				Aliases:    []string{},
				Tags:       []string{},
				Metadata:   map[string]any{},
			})
			require.NoError(t, err)
			want[keyID+"@"+engineID] = true
		}
	}

	got := map[string]bool{}
	_, err = store.SelectAll(ctx, storage.StorageListRequest[models.Key]{
		ExhaustiveRun: true,
		QueryParams:   &resources.QueryParameters{PageSize: 2},
		ApplyFunc: func(k models.Key) {
			id := k.KeyID + "@" + k.EngineID
			assert.False(t, got[id], "key %s visited twice", id)
			got[id] = true
		},
	})
	require.NoError(t, err)
	assert.Equal(t, want, got)
}
