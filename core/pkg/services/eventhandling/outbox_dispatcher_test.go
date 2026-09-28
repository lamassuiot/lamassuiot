package eventhandling

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/stretchr/testify/assert"
)

type fakeOutboxRepo struct {
	records       []models.EventOutboxRecord
	published     []string
	retries       []string
	failed        []string
	nextAvailable time.Time
}

func (repo *fakeOutboxRepo) Enqueue(context.Context, *models.EventOutboxRecord) error { return nil }
func (repo *fakeOutboxRepo) ClaimPending(context.Context, int) ([]models.EventOutboxRecord, error) {
	return repo.records, nil
}
func (repo *fakeOutboxRepo) MarkPublished(_ context.Context, eventID string) error {
	repo.published = append(repo.published, eventID)
	return nil
}
func (repo *fakeOutboxRepo) ScheduleRetry(_ context.Context, eventID string, _ string, availableAt time.Time) error {
	repo.retries = append(repo.retries, eventID)
	repo.nextAvailable = availableAt
	return nil
}
func (repo *fakeOutboxRepo) MarkFailed(_ context.Context, eventID string, _ string) error {
	repo.failed = append(repo.failed, eventID)
	return nil
}

func outboxTestContext() context.Context {
	return core.WithTenantContext(context.Background(), core.TenantContext{
		OrganizationID: "org-a",
		TenantID:       "tenant-a",
		ActorID:        "worker",
		ActorType:      "system",
		CorrelationID:  "correlation-a",
		Source:         "outbox-test",
		TenantStatus:   core.TenantActive,
		Validated:      true,
	})
}

func TestOutboxDispatcherSchedulesRetryAndPreservesEvent(t *testing.T) {
	repo := &fakeOutboxRepo{records: []models.EventOutboxRecord{{
		EventID:        "event-1",
		TenantID:       "tenant-a",
		OrganizationID: "org-a",
		Attempts:       1,
		Payload:        []byte(`{"value":"same"}`),
	}}}
	dispatcher := OutboxDispatcher{
		MaxAttempts: 3,
		Backoff:     func(int) time.Duration { return time.Minute },
		Publish:     func(context.Context, models.EventOutboxRecord) error { return errors.New("broker unavailable") },
	}

	err := dispatcher.Dispatch(outboxTestContext(), repo, 10)
	assert.NoError(t, err)
	assert.Equal(t, []string{"event-1"}, repo.retries)
	assert.Empty(t, repo.failed)
	assert.WithinDuration(t, time.Now().Add(time.Minute), repo.nextAvailable, 2*time.Second)
}

func TestOutboxDispatcherRejectsAnotherTenantBeforePublish(t *testing.T) {
	repo := &fakeOutboxRepo{records: []models.EventOutboxRecord{{
		EventID:        "event-2",
		TenantID:       "tenant-b",
		OrganizationID: "org-a",
		Attempts:       1,
		Payload:        []byte(`{"value":"secret"}`),
	}}}
	published := false
	dispatcher := OutboxDispatcher{Publish: func(context.Context, models.EventOutboxRecord) error {
		published = true
		return nil
	}}

	err := dispatcher.Dispatch(outboxTestContext(), repo, 10)
	assert.NoError(t, err)
	assert.False(t, published)
	assert.Equal(t, []string{"event-2"}, repo.failed)
}
