package store

import (
	"context"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/device-manager/common/dto"
)

type StatsDB interface {
	GetStats(ctx context.Context) (dto.Stats, time.Time, error)
	UpdateStats(ctx context.Context, stats dto.Stats) error
}
