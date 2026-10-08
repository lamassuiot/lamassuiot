package sqlite

import (
	"context"
	"database/sql"
	"sync"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// Reuse the shared SQL queries, with SQLite-specific coordination.
type caStore struct {
	storage.CACertificatesRepo
	db *gorm.DB
}

func newCARepository(log *logrus.Entry, db *gorm.DB) (storage.CACertificatesRepo, error) {
	repo, err := postgres.NewCAPostgresRepository(log, db)
	if err != nil {
		return nil, err
	}
	return &caStore{CACertificatesRepo: repo, db: db}, nil
}

type caIDLockKey struct {
	pool *sql.DB
	id   string
}

type caIDLock struct {
	token chan struct{}
	refs  int
}

// Coordinate repository instances sharing a pool, not separate processes.
var caIDLocks = struct {
	sync.Mutex
	locks map[caIDLockKey]*caIDLock
}{locks: make(map[caIDLockKey]*caIDLock)}

func (store *caStore) WithIDLock(ctx context.Context, id string, fn func(storage.CACertificatesRepo) error) error {
	pool, err := store.db.DB()
	if err != nil {
		return err
	}
	key := caIDLockKey{pool: pool, id: id}
	caIDLocks.Lock()
	lock := caIDLocks.locks[key]
	if lock == nil {
		lock = &caIDLock{token: make(chan struct{}, 1)}
		caIDLocks.locks[key] = lock
	}
	lock.refs++
	caIDLocks.Unlock()
	defer func() {
		caIDLocks.Lock()
		defer caIDLocks.Unlock()
		lock.refs--
		if lock.refs == 0 {
			delete(caIDLocks.locks, key)
		}
	}()
	select {
	case lock.token <- struct{}{}:
		defer func() { <-lock.token }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Leave the single connection available to KMS during the callback.
	return fn(store)
}
