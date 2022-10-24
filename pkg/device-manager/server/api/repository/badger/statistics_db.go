package badger

import (
	"context"
	"encoding/json"
	"time"

	badger "github.com/dgraph-io/badger/v3"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/device-manager/server/api/repository"
)

type BadgerDB struct {
	db *badger.DB
}

const (
	StatsContentKey = "StatsContentKey"
)

type StatsContent struct {
	Stats    api.DevicesManagerStats
	ScanDate time.Time
}

func NewStatisticsDBInMemory() (repository.Statistics, error) {
	db, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))

	if err != nil {
		return nil, err
	}

	return &BadgerDB{
		db: db,
	}, nil
}

func (b *BadgerDB) UpdateStatistics(ctx context.Context, stats api.DevicesManagerStats) error {
	err := b.db.Update(func(txn *badger.Txn) error {
		statsContent := StatsContent{
			Stats:    stats,
			ScanDate: time.Now(),
		}

		bytes, err := json.Marshal(statsContent)
		if err != nil {
			return err
		}

		e := badger.NewEntry([]byte(StatsContentKey), []byte(bytes))
		err = txn.SetEntry(e)
		if err != nil {
			return err
		}

		return nil
	})

	return err
}

func (b *BadgerDB) GetStatistics(ctx context.Context) (api.DevicesManagerStats, time.Time, error) {
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
		if err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return api.DevicesManagerStats{}, time.Now(), err
	}

	var valMap StatsContent
	if err := json.Unmarshal([]byte(string(valCopy)), &valMap); err != nil {
		return api.DevicesManagerStats{}, time.Now(), err
	}

	return valMap.Stats, valMap.ScanDate, nil
}
