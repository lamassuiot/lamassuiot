package oracle

import (
	"context"
	"regexp"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"gorm.io/gorm"
)

type eventStore struct{ db *gorm.DB }
type subscriptionStore struct{ db *gorm.DB }

var _ storage.EventRepository = (*eventStore)(nil)
var _ storage.SubscriptionsRepository = (*subscriptionStore)(nil)

var eventPK = regexp.MustCompile(`(?i)\([^)]*\blamassu_event_pk\)`)
var subscriptionPK = regexp.MustCompile(`(?i)\([^)]*\blamassu_subscription_pk\)`)
var eventFields = map[string]struct{}{"event_type": {}, "last_seen": {}, "total_seen": {}, "event": {}}
var eventSortFields = map[string]struct{}{"event_type": {}, "last_seen": {}, "total_seen": {}}
var eventFieldAliases = map[string]string{"seen_at": "last_seen", "counter": "total_seen"}
var subscriptionFields = map[string]struct{}{"id": {}, "user_id": {}, "event_type": {}, "subscription_date": {}, "conditions": {}, "channel": {}}
var subscriptionSortFields = map[string]struct{}{"id": {}, "user_id": {}, "event_type": {}, "subscription_date": {}}

func (s *eventStore) GetLatestEventByEventType(ctx context.Context, eventType models.EventType) (bool, *models.AlertLatestEvent, error) {
	var event models.AlertLatestEvent
	tx := s.db.WithContext(ctx).Table("events").Where("event_type = ?", eventType).Limit(1).Find(&event)
	if tx.Error != nil {
		return false, nil, tx.Error
	}
	if tx.RowsAffected == 0 {
		return false, nil, nil
	}
	return true, &event, nil
}

func (s *eventStore) InsertUpdateEvent(ctx context.Context, event *models.AlertLatestEvent) (*models.AlertLatestEvent, error) {
	update := func() *gorm.DB {
		return s.db.WithContext(ctx).Table("events").Where("event_type = ?", event.EventType).Select("*").Updates(event)
	}
	tx := update()
	if tx.Error != nil {
		return nil, tx.Error
	}
	if tx.RowsAffected == 1 {
		return event, nil
	}
	if err := s.db.WithContext(ctx).Table("events").Create(event).Error; err != nil {
		// Another writer can insert between our update and insert. Retry the
		// update rather than relying on an unsupported GORM upsert clause.
		if !constraintError(err, "ORA-00001", eventPK) {
			return nil, err
		}
		tx = update()
		if tx.Error != nil {
			return nil, tx.Error
		}
		if tx.RowsAffected != 1 {
			return nil, gorm.ErrRecordNotFound
		}
	}
	return event, nil
}

func (s *eventStore) GetLatestEvents(ctx context.Context, req storage.StorageListRequest[models.AlertLatestEvent]) (string, error) {
	return listRows(s.db.WithContext(ctx).Table("events"), req, eventFields, eventSortFields, nil, eventFieldAliases, []string{"event_type"}, func(event models.AlertLatestEvent) []any { return []any{event.EventType} })
}

func (s *subscriptionStore) list(tx *gorm.DB, exhaustive bool, apply func(models.Subscription), params *resources.QueryParameters, opts map[string]any) (string, error) {
	req := storage.StorageListRequest[models.Subscription]{ExhaustiveRun: exhaustive, ApplyFunc: apply, QueryParams: params, ExtraOpts: opts}
	return listRows(tx, req, subscriptionFields, subscriptionSortFields, nil, nil, []string{"id"}, func(sub models.Subscription) []any { return []any{sub.ID} })
}

func (s *subscriptionStore) GetSubscriptions(ctx context.Context, user string, exhaustive bool, apply func(models.Subscription), params *resources.QueryParameters, opts map[string]any) (string, error) {
	return s.list(s.db.WithContext(ctx).Table("subscriptions").Where("user_id = ?", user), exhaustive, apply, params, opts)
}

func (s *subscriptionStore) GetSubscriptionsByEventType(ctx context.Context, eventType string, exhaustive bool, apply func(models.Subscription), params *resources.QueryParameters, opts map[string]any) (string, error) {
	return s.list(s.db.WithContext(ctx).Table("subscriptions").Where("event_type = ?", eventType), exhaustive, apply, params, opts)
}

func (s *subscriptionStore) Subscribe(ctx context.Context, sub *models.Subscription) (*models.Subscription, error) {
	if err := s.db.WithContext(ctx).Table("subscriptions").Create(sub).Error; err != nil {
		if constraintError(err, "ORA-00001", subscriptionPK) {
			return nil, gorm.ErrDuplicatedKey
		}
		return nil, err
	}
	return sub, nil
}

func (s *subscriptionStore) Unsubscribe(ctx context.Context, id string) error {
	tx := s.db.WithContext(ctx).Table("subscriptions").Where("id = ?", id).Delete(&models.Subscription{})
	if tx.Error != nil {
		return tx.Error
	}
	if tx.RowsAffected != 1 {
		return gorm.ErrRecordNotFound
	}
	return nil
}
