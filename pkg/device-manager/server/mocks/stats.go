package mocks

import (
	"context"
	"errors"
	"time"

	badger "github.com/dgraph-io/badger/v3"

	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/models/device/store"
)

type BadgerMockDB struct {
	db *badger.DB
}

const (
	StatsContentKey = "StatsContentKey"
)

type StatsMockContent struct {
	Stats    dto.Stats
	ScanDate time.Time
}

func NewInMemoryMockDB() (store.StatsDB, error) {
	db, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))

	if err != nil {
		return nil, err
	}

	return &BadgerMockDB{
		db: db,
	}, nil
}

func (b *BadgerMockDB) UpdateStats(ctx context.Context, stats dto.Stats) error {
	if ctx.Value("DBUpdateStats") != nil {
		failDBLog := ctx.Value("DBUpdateStats").(bool)
		if failDBLog {
			return errors.New("Error Update Stats")
		}
	}
	return nil
}

func (b *BadgerMockDB) GetStats(ctx context.Context) (dto.Stats, time.Time, error) {
	if ctx.Value("DBGetStats") != nil {
		failDBLog := ctx.Value("DBGetStats").(bool)
		if failDBLog {
			return dto.Stats{}, time.Time{}, errors.New("Error Getting Stats")
		}
	}
	return dto.Stats{}, time.Time{}, nil
}
