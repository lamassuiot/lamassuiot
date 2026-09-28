package storage

import (
	"context"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

type EventOutboxRepo interface {
	Enqueue(ctx context.Context, record *models.EventOutboxRecord) error
	ClaimPending(ctx context.Context, limit int) ([]models.EventOutboxRecord, error)
	MarkPublished(ctx context.Context, eventID string) error
	ScheduleRetry(ctx context.Context, eventID string, reason string, availableAt time.Time) error
	MarkFailed(ctx context.Context, eventID string, reason string) error
}
