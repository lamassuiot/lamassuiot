package postgres

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	postgrestest "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/test"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type lockProbe struct {
	ID      string `gorm:"primaryKey"`
	Counter int
}

// newLockProbeQueriers returns two queriers over the same table, each backed
// by its own connection pool (as two service replicas would be), plus a
// querier for a second table that reuses the same IDs.
func newLockProbeQueriers(t *testing.T) (a, b *DBQuerier[lockProbe], otherTable *DBQuerier[lockProbe], db *gorm.DB) {
	t.Helper()
	config, suite := postgrestest.BeforeSuite([]string{"ca"}, false)
	t.Cleanup(suite.AfterSuite)
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	log := logrus.NewEntry(logger)

	db = suite.DB["ca"]
	pool, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pool.Close()) })

	otherDB, err := CreatePostgresDBConnection(log, config, "ca")
	require.NoError(t, err)
	otherPool, err := otherDB.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, otherPool.Close()) })

	for _, table := range []string{"lock_probe", "lock_probe_other"} {
		require.NoError(t, db.Exec("CREATE TABLE "+table+" (id text PRIMARY KEY, counter int NOT NULL DEFAULT 0)").Error)
	}

	a, err = TableQuery(log, db, "lock_probe", "id", lockProbe{})
	require.NoError(t, err)
	b, err = TableQuery(log, otherDB, "lock_probe", "id", lockProbe{})
	require.NoError(t, err)
	otherTable, err = TableQuery(log, otherDB, "lock_probe_other", "id", lockProbe{})
	require.NoError(t, err)
	return a, b, otherTable, db
}

func counterOf(t *testing.T, db *gorm.DB, table, id string) int {
	t.Helper()
	var counter int
	require.NoError(t, db.Raw("SELECT counter FROM "+table+" WHERE id = ?", id).Scan(&counter).Error)
	return counter
}

func waitingAdvisoryLocks(db *gorm.DB) int64 {
	var waiting int64
	if err := db.Raw("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted").Scan(&waiting).Error; err != nil {
		return -1
	}
	return waiting
}

// subtestCtx gives every subtest its own deadline so a slow or stuck one
// cannot consume the budget of the others.
func subtestCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// await receives from ch, failing the test instead of hanging when ctx expires.
func await[T any](t *testing.T, ctx context.Context, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-ctx.Done():
		t.Fatalf("timed out waiting for result: %v", ctx.Err())
		panic("unreachable")
	}
}

// holdLock acquires the ID lock in the background and returns once the
// callback is running (or fails the test if it never gets there: the lock
// call returned early with an error, or ctx expired). The returned release
// ends the callback, optionally after running work inside the lock-owning
// transaction, and returns the lock call's result. It is also registered as
// a cleanup so the holder never outlives the subtest.
func holdLock(t *testing.T, ctx context.Context, q *DBQuerier[lockProbe], id string, work func(*gorm.DB) error) (release func() error) {
	t.Helper()
	held, releaseCh, result := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		result <- q.WithIDLock(ctx, id, func(s *DBQuerier[lockProbe]) error {
			close(held)
			select {
			case <-releaseCh:
			case <-ctx.Done():
				return ctx.Err()
			}
			if work != nil {
				return work(s.DB)
			}
			return nil
		})
	}()

	select {
	case <-held:
	case err := <-result:
		t.Fatalf("lock call returned before the callback ran: %v", err)
	case <-ctx.Done():
		t.Fatalf("lock holder did not start: %v", ctx.Err())
	}

	var once sync.Once
	var err error
	release = func() error {
		once.Do(func() {
			close(releaseCh)
			err = await(t, ctx, result)
		})
		return err
	}
	t.Cleanup(func() { _ = release() })
	return release
}

func TestDBQuerierWithIDLock(t *testing.T) {
	a, b, otherTable, db := newLockProbeQueriers(t)

	require.NoError(t, db.Exec("INSERT INTO lock_probe (id, counter) VALUES ('shared', 0), ('other', 0)").Error)
	require.NoError(t, db.Exec("INSERT INTO lock_probe_other (id, counter) VALUES ('shared', 0)").Error)

	noop := func(*DBQuerier[lockProbe]) error { return nil }

	t.Run("serializes the same ID across independent connection pools", func(t *testing.T) {
		ctx := subtestCtx(t)
		const workers = 10
		var wg sync.WaitGroup
		errc := make(chan error, workers)
		for i := 0; i < workers; i++ {
			q := a
			if i%2 == 1 {
				q = b
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				// A read-modify-write that loses updates without mutual exclusion.
				errc <- q.WithIDLock(ctx, "shared", func(s *DBQuerier[lockProbe]) error {
					var counter int
					if err := s.DB.Raw("SELECT counter FROM lock_probe WHERE id = 'shared'").Scan(&counter).Error; err != nil {
						return err
					}
					time.Sleep(5 * time.Millisecond)
					return s.DB.Exec("UPDATE lock_probe SET counter = ? WHERE id = 'shared'", counter+1).Error
				})
			}()
		}
		wg.Wait()
		close(errc)
		for err := range errc {
			require.NoError(t, err)
		}
		require.Equal(t, workers, counterOf(t, db, "lock_probe", "shared"), "a concurrent update was lost")
	})

	t.Run("does not block other IDs", func(t *testing.T) {
		ctx := subtestCtx(t)
		release := holdLock(t, ctx, a, "shared", nil)
		other, cancelOther := context.WithTimeout(ctx, 2*time.Second)
		defer cancelOther()
		require.NoError(t, b.WithIDLock(other, "other", noop))
		require.NoError(t, release())
	})

	t.Run("does not block the same ID of another table", func(t *testing.T) {
		ctx := subtestCtx(t)
		release := holdLock(t, ctx, a, "shared", nil)
		other, cancelOther := context.WithTimeout(ctx, 2*time.Second)
		defer cancelOther()
		require.NoError(t, otherTable.WithIDLock(other, "shared", noop))
		require.NoError(t, release())
	})

	t.Run("waiter blocks in PostgreSQL until the holder commits and then sees its writes", func(t *testing.T) {
		ctx := subtestCtx(t)
		release := holdLock(t, ctx, a, "shared", func(tx *gorm.DB) error {
			return tx.Exec("UPDATE lock_probe SET counter = 1000 WHERE id = 'shared'").Error
		})

		var seen int
		waiter := make(chan error, 1)
		go func() {
			waiter <- b.WithIDLock(ctx, "shared", func(s *DBQuerier[lockProbe]) error {
				return s.DB.Raw("SELECT counter FROM lock_probe WHERE id = 'shared'").Scan(&seen).Error
			})
		}()
		require.Eventually(t, func() bool { return waitingAdvisoryLocks(db) > 0 }, 3*time.Second, 10*time.Millisecond)
		select {
		case err := <-waiter:
			t.Fatalf("waiter ran while the lock was held: %v", err)
		default:
		}

		require.NoError(t, release())
		require.NoError(t, await(t, ctx, waiter))
		require.Equal(t, 1000, seen, "the waiter must observe the committed write of the previous holder")
	})

	t.Run("callback runs in a transaction that rolls back on error and releases the lock", func(t *testing.T) {
		ctx := subtestCtx(t)
		injected := errors.New("boom")
		err := a.WithIDLock(ctx, "other", func(s *DBQuerier[lockProbe]) error {
			require.NoError(t, s.DB.Exec("UPDATE lock_probe SET counter = 77 WHERE id = 'other'").Error)
			return injected
		})
		require.ErrorIs(t, err, injected)
		require.Equal(t, 0, counterOf(t, db, "lock_probe", "other"), "writes of a failed callback must be rolled back")

		again, cancelAgain := context.WithTimeout(ctx, 2*time.Second)
		defer cancelAgain()
		require.NoError(t, b.WithIDLock(again, "other", noop), "lock must be released after rollback")
	})

	t.Run("callback querier is a copy bound to the transaction", func(t *testing.T) {
		ctx := subtestCtx(t)
		require.NoError(t, a.WithIDLock(ctx, "other", func(s *DBQuerier[lockProbe]) error {
			require.NotSame(t, a, s)
			require.NotSame(t, a.DB, s.DB)
			require.Equal(t, a.tableName, s.tableName)
			require.Equal(t, a.primaryKeyColumn, s.primaryKeyColumn)
			return nil
		}))
	})

	t.Run("a cancelled waiter gives up without running the callback", func(t *testing.T) {
		ctx := subtestCtx(t)
		release := holdLock(t, ctx, a, "shared", nil)

		waiting, cancelWaiting := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancelWaiting()
		ran := false
		err := b.WithIDLock(waiting, "shared", func(*DBQuerier[lockProbe]) error { ran = true; return nil })
		require.Error(t, err)
		require.False(t, ran)

		require.NoError(t, release())
	})

	t.Run("WithIDLock and WithLocks share the ID key", func(t *testing.T) {
		ctx := subtestCtx(t)
		release := holdLock(t, ctx, a, "shared", nil)

		waiting, cancelWaiting := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancelWaiting()
		ran := false
		err := b.WithLocks(waiting, []string{storage.IDLockKey("shared"), "extra"}, func(*DBQuerier[lockProbe]) error { ran = true; return nil })
		require.Error(t, err)
		require.False(t, ran)
		require.NoError(t, release())
	})

	t.Run("WithLocks excludes callers that share any key", func(t *testing.T) {
		ctx := subtestCtx(t)
		var wg sync.WaitGroup
		errc := make(chan error, 6)
		keySets := [][]string{{"x", "y"}, {"y", "z"}, {"z", "x"}}
		for i := 0; i < 6; i++ {
			q, keys := a, keySets[i%3]
			if i%2 == 1 {
				q = b
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				// Every key set overlaps with the others, so all callers contend
				// and must serialize on the shared counter.
				errc <- q.WithLocks(ctx, keys, func(s *DBQuerier[lockProbe]) error {
					var counter int
					if err := s.DB.Raw("SELECT counter FROM lock_probe WHERE id = 'other'").Scan(&counter).Error; err != nil {
						return err
					}
					time.Sleep(5 * time.Millisecond)
					return s.DB.Exec("UPDATE lock_probe SET counter = ? WHERE id = 'other'", counter+1).Error
				})
			}()
		}
		wg.Wait()
		close(errc)
		for err := range errc {
			require.NoError(t, err)
		}
		require.Equal(t, 6, counterOf(t, db, "lock_probe", "other"), "a concurrent update was lost")
	})

	t.Run("WithLocks acquires crossed key orders without deadlock and tolerates duplicate keys", func(t *testing.T) {
		ctx := subtestCtx(t)
		results := make(chan error, 2)
		go func() { results <- a.WithLocks(ctx, []string{"p", "q", "p"}, noop) }()
		go func() { results <- b.WithLocks(ctx, []string{"q", "p"}, noop) }()
		require.NoError(t, await(t, ctx, results))
		require.NoError(t, await(t, ctx, results))
	})
}
