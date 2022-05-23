package db

import (
	"context"
	"encoding/json"
	"time"

	badger "github.com/dgraph-io/badger/v3"

	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/dto"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/models/device/store"
)

type BadgerDB struct {
	db *badger.DB
}

const (
	StatsContentKey = "StatsContentKey"
)

type StatsContent struct {
	Stats    dto.Stats
	ScanDate time.Time
}

func NewInMemoryDB() (store.StatsDB, error) {
	db, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))

	if err != nil {
		return nil, err
	}

	return &BadgerDB{
		db: db,
	}, nil
}

func (b *BadgerDB) UpdateStats(ctx context.Context, stats dto.Stats) error {
	err := b.db.Update(func(txn *badger.Txn) error {
		statsContent := StatsContent{
			Stats:    stats,
			ScanDate: time.Now(),
		}

		bytes, err := json.Marshal(statsContent)
		if err != nil {
			return err
		}

		e := badger.NewEntry([]byte(StatsContentKey), []byte(bytes)).WithTTL(time.Hour)
		err = txn.SetEntry(e)

		return nil
	})

	return err
}

func (b *BadgerDB) GetStats(ctx context.Context) (dto.Stats, time.Time, error) {
	var valCopy []byte

	err := b.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(StatsContentKey))
		if err != nil {
			return err
		}

		err = item.Value(func(val []byte) error {
			valCopy = append([]byte{}, val...)
			return nil
		})

		return nil
	})

	if err != nil {
		return dto.Stats{}, time.Now(), err
	}

	var valMap StatsContent
	if err := json.Unmarshal([]byte(string(valCopy)), &valMap); err != nil {
		return dto.Stats{}, time.Now(), err
	}

	return valMap.Stats, valMap.ScanDate, nil
}
