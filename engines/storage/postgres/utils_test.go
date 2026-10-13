package postgres

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	postgrestest "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/test"
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

func TestDBQuerierWithIDLock(t *testing.T) {
	a, b, otherTable, db := newLockProbeQueriers(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	require.NoError(t, db.Exec("INSERT INTO lock_probe (id, counter) VALUES ('shared', 0), ('other', 0)").Error)
	require.NoError(t, db.Exec("INSERT INTO lock_probe_other (id, counter) VALUES ('shared', 0)").Error)

	// increment is a read-modify-write that would lose updates without mutual exclusion.
	increment := func(table string) func(*gorm.DB) error {
		return func(tx *gorm.DB) error {
			var counter int
			if err := tx.Raw("SELECT counter FROM " + table + " WHERE id = 'shared'").Scan(&counter).Error; err != nil {
				return err
			}
			time.Sleep(5 * time.Millisecond)
			return tx.Exec("UPDATE "+table+" SET counter = ? WHERE id = 'shared'", counter+1).Error
		}
	}

	t.Run("serializes the same ID across independent connection pools", func(t *testing.T) {
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
				errc <- q.WithIDLock(ctx, "shared", func(s *DBQuerier[lockProbe]) error {
					return increment("lock_probe")(s.DB)
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
		held, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
		go func() {
			done <- a.WithIDLock(ctx, "shared", func(*DBQuerier[lockProbe]) error {
				close(held)
				<-release
				return nil
			})
		}()
		<-held
		other, cancelOther := context.WithTimeout(ctx, 2*time.Second)
		defer cancelOther()
		require.NoError(t, b.WithIDLock(other, "other", func(*DBQuerier[lockProbe]) error { return nil }))
		close(release)
		require.NoError(t, <-done)
	})

	t.Run("does not block the same ID of another table", func(t *testing.T) {
		held, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
		go func() {
			done <- a.WithIDLock(ctx, "shared", func(*DBQuerier[lockProbe]) error {
				close(held)
				<-release
				return nil
			})
		}()
		<-held
		other, cancelOther := context.WithTimeout(ctx, 2*time.Second)
		defer cancelOther()
		require.NoError(t, otherTable.WithIDLock(other, "shared", func(*DBQuerier[lockProbe]) error { return nil }))
		close(release)
		require.NoError(t, <-done)
	})

	t.Run("waiter blocks in PostgreSQL until the holder commits and then sees its writes", func(t *testing.T) {
		held, release, holder := make(chan struct{}), make(chan struct{}), make(chan error, 1)
		go func() {
			holder <- a.WithIDLock(ctx, "shared", func(s *DBQuerier[lockProbe]) error {
				close(held)
				<-release
				return s.DB.Exec("UPDATE lock_probe SET counter = 1000 WHERE id = 'shared'").Error
			})
		}()
		<-held

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

		close(release)
		require.NoError(t, <-holder)
		require.NoError(t, <-waiter)
		require.Equal(t, 1000, seen, "the waiter must observe the committed write of the previous holder")
	})

	t.Run("callback runs in a transaction that rolls back on error and releases the lock", func(t *testing.T) {
		injected := errors.New("boom")
		err := a.WithIDLock(ctx, "other", func(s *DBQuerier[lockProbe]) error {
			require.NoError(t, s.DB.Exec("UPDATE lock_probe SET counter = 77 WHERE id = 'other'").Error)
			return injected
		})
		require.ErrorIs(t, err, injected)
		require.Equal(t, 0, counterOf(t, db, "lock_probe", "other"), "writes of a failed callback must be rolled back")

		again, cancelAgain := context.WithTimeout(ctx, 2*time.Second)
		defer cancelAgain()
		require.NoError(t, b.WithIDLock(again, "other", func(*DBQuerier[lockProbe]) error { return nil }), "lock must be released after rollback")
	})

	t.Run("callback querier is a copy bound to the transaction", func(t *testing.T) {
		require.NoError(t, a.WithIDLock(ctx, "other", func(s *DBQuerier[lockProbe]) error {
			require.NotSame(t, a, s)
			require.NotSame(t, a.DB, s.DB)
			require.Equal(t, a.tableName, s.tableName)
			require.Equal(t, a.primaryKeyColumn, s.primaryKeyColumn)
			return nil
		}))
	})

	t.Run("a cancelled waiter gives up without running the callback", func(t *testing.T) {
		held, release, holder := make(chan struct{}), make(chan struct{}), make(chan error, 1)
		go func() {
			holder <- a.WithIDLock(ctx, "shared", func(*DBQuerier[lockProbe]) error {
				close(held)
				<-release
				return nil
			})
		}()
		<-held

		waiting, cancelWaiting := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancelWaiting()
		ran := false
		err := b.WithIDLock(waiting, "shared", func(*DBQuerier[lockProbe]) error { ran = true; return nil })
		require.Error(t, err)
		require.False(t, ran)

		close(release)
		require.NoError(t, <-holder)
	})
}
