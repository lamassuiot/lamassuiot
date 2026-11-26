package postgrestest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The lock of an RA is held in the database, so two instances of the DMS Manager wait for each other.
func TestDMSStoreWithLock(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgres.DMS_SCHEMA}, false)
	t.Cleanup(suite.AfterSuite)
	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Test")
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.DMS_SCHEMA))
	store, err := postgres.NewDMSManagerRepository(logger, suite.DB[postgres.DMS_SCHEMA])
	require.NoError(t, err)
	ctx := context.Background()

	t.Run("the error of the function comes back", func(t *testing.T) {
		boom := errors.New("boom")
		assert.ErrorIs(t, store.WithLock(ctx, "ra-1", func() error { return boom }), boom)
		assert.NoError(t, store.WithLock(ctx, "ra-1", func() error { return nil }), "and the lock is free again")
	})

	t.Run("the same RA waits, another does not", func(t *testing.T) {
		holding, release := make(chan struct{}), make(chan struct{})
		go func() { _ = store.WithLock(ctx, "ra-1", func() error { close(holding); <-release; return nil }) }()
		<-holding

		ran := func(id string) chan struct{} {
			done := make(chan struct{})
			go func() { _ = store.WithLock(ctx, id, func() error { close(done); return nil }) }()
			return done
		}
		same, other := ran("ra-1"), ran("ra-2")
		select {
		case <-other:
		case <-time.After(5 * time.Second):
			t.Fatal("another RA waited for the lock")
		}
		select {
		case <-same:
			t.Fatal("the same RA did not wait")
		case <-time.After(300 * time.Millisecond):
		}
		close(release)
		select {
		case <-same:
		case <-time.After(5 * time.Second):
			t.Fatal("the lock was not released")
		}
	})
}
