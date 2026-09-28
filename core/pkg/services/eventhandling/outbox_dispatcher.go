package eventhandling

import (
	"context"
	"fmt"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

type OutboxPublisher func(context.Context, models.EventOutboxRecord) error

type OutboxDispatcher struct {
	MaxAttempts int
	Backoff     func(attempt int) time.Duration
	Publish     OutboxPublisher
}

func (dispatcher OutboxDispatcher) Dispatch(ctx context.Context, repo storage.EventOutboxRepo, limit int) error {
	if dispatcher.Publish == nil {
		return fmt.Errorf("outbox publisher is required")
	}
	if dispatcher.MaxAttempts <= 0 {
		dispatcher.MaxAttempts = 3
	}
	if dispatcher.Backoff == nil {
		dispatcher.Backoff = func(attempt int) time.Duration {
			return time.Duration(attempt) * time.Second
		}
	}
	records, err := repo.ClaimPending(ctx, limit)
	if err != nil {
		return err
	}
	for _, record := range records {
		if err := validateOutboxScope(ctx, record); err != nil {
			if markErr := repo.MarkFailed(ctx, record.EventID, err.Error()); markErr != nil {
				return markErr
			}
			continue
		}
		if err := dispatcher.Publish(ctx, record); err == nil {
			if err := repo.MarkPublished(ctx, record.EventID); err != nil {
				return err
			}
		} else if record.Attempts >= dispatcher.MaxAttempts {
			if markErr := repo.MarkFailed(ctx, record.EventID, err.Error()); markErr != nil {
				return markErr
			}
		} else if retryErr := repo.ScheduleRetry(ctx, record.EventID, err.Error(), time.Now().UTC().Add(dispatcher.Backoff(record.Attempts))); retryErr != nil {
			return retryErr
		}
	}
	return nil
}

func validateOutboxScope(ctx context.Context, record models.EventOutboxRecord) error {
	tenantContext, err := core.RequireTenantContext(ctx)
	if err != nil {
		return err
	}
	if tenantContext.TenantID != record.TenantID || tenantContext.OrganizationID != record.OrganizationID {
		return ErrConflictingEventReplay
	}
	return nil
}
