package oracle

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"gorm.io/gorm"
)

func testAlerts(t *testing.T, ctx context.Context, db *gorm.DB) {
	t.Helper()
	subs := &subscriptionStore{db: db}
	now := time.Now().UTC().Truncate(time.Second)
	sub := &models.Subscription{ID: "sub-a", UserID: "user-a", EventType: models.EventType("certificate.create"), SubscriptionDate: now, Conditions: []models.SubscriptionCondition{{Type: models.JSONPath, Condition: `$.status == "ACTIVE"`}}, Channel: models.Channel{Type: models.ChannelTypeWebhook, Name: "webhook", Config: map[string]any{"url": "https://example.test/hook"}}}
	if _, err := subs.Subscribe(ctx, sub); err != nil {
		t.Fatal(err)
	}
	if _, err := subs.Subscribe(ctx, sub); !errors.Is(err, gorm.ErrDuplicatedKey) {
		t.Fatalf("duplicate subscription: %v", err)
	}
	second := *sub
	second.ID = "sub-b"
	if _, err := subs.Subscribe(ctx, &second); err != nil {
		t.Fatal(err)
	}
	other := *sub
	other.ID, other.UserID = "sub-c", "user-b"
	if _, err := subs.Subscribe(ctx, &other); err != nil {
		t.Fatal(err)
	}
	params := &resources.QueryParameters{PageSize: 1}
	var ids []string
	bookmark, err := subs.GetSubscriptions(ctx, "user-a", false, func(s models.Subscription) {
		ids = append(ids, s.ID)
		if !reflect.DeepEqual(s.Conditions, sub.Conditions) || s.Channel.Type != sub.Channel.Type {
			t.Errorf("subscription round trip: %+v", s)
		}
	}, params, nil)
	if err != nil || bookmark == "" {
		t.Fatalf("subscription first page: bookmark=%q error=%v", bookmark, err)
	}
	params.NextBookmark = bookmark
	bookmark, err = subs.GetSubscriptions(ctx, "user-a", false, func(s models.Subscription) { ids = append(ids, s.ID) }, params, nil)
	if err != nil || bookmark != "" || !reflect.DeepEqual(ids, []string{"sub-a", "sub-b"}) {
		t.Fatalf("subscription pages=%v bookmark=%q error=%v", ids, bookmark, err)
	}
	ids = nil
	if _, err := subs.GetSubscriptionsByEventType(ctx, "certificate.create", true, func(s models.Subscription) { ids = append(ids, s.ID) }, &resources.QueryParameters{PageSize: 1}, nil); err != nil || !reflect.DeepEqual(ids, []string{"sub-a", "sub-b", "sub-c"}) {
		t.Fatalf("subscriptions by event=%v error=%v", ids, err)
	}
	for _, id := range []string{"sub-a", "sub-b", "sub-c"} {
		if err := subs.Unsubscribe(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := subs.Unsubscribe(ctx, "sub-c"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("missing subscription: %v", err)
	}

	events := &eventStore{db: db}
	cloudEvent := cloudevents.NewEvent()
	cloudEvent.SetID("event-1")
	cloudEvent.SetSource("service/test")
	cloudEvent.SetType("certificate.create")
	if err := cloudEvent.SetData(cloudevents.ApplicationJSON, map[string]any{"serial": "123"}); err != nil {
		t.Fatal(err)
	}
	latest := &models.AlertLatestEvent{EventType: models.EventType("certificate.create"), Event: cloudEvent, LastSeen: now, TotalSeen: 1}
	if _, err := events.InsertUpdateEvent(ctx, latest); err != nil {
		t.Fatal(err)
	}
	latest.TotalSeen = 5
	if _, err := events.InsertUpdateEvent(ctx, latest); err != nil {
		t.Fatal(err)
	}
	found, read, err := events.GetLatestEventByEventType(ctx, latest.EventType)
	if err != nil || !found || read.TotalSeen != 5 || read.Event.ID() != "event-1" || !read.LastSeen.Equal(now) {
		t.Fatalf("latest event: found=%v event=%+v error=%v", found, read, err)
	}
	secondEvent := *latest
	secondEvent.EventType = models.EventType("device.create")
	secondEvent.TotalSeen = 7
	if _, err := events.InsertUpdateEvent(ctx, &secondEvent); err != nil {
		t.Fatal(err)
	}
	var eventTypes []models.EventType
	query := &resources.QueryParameters{PageSize: 1, Sort: resources.SortOptions{SortField: "counter", SortMode: resources.SortModeDesc}, Filters: []resources.FilterOption{{Field: "counter", FilterOperation: resources.NumberGreaterThan, Value: "0"}}}
	req := storage.StorageListRequest[models.AlertLatestEvent]{QueryParams: query, ApplyFunc: func(e models.AlertLatestEvent) { eventTypes = append(eventTypes, e.EventType) }}
	bookmark, err = events.GetLatestEvents(ctx, req)
	if err != nil || bookmark == "" {
		t.Fatalf("event first page: bookmark=%q error=%v", bookmark, err)
	}
	query.NextBookmark = bookmark
	bookmark, err = events.GetLatestEvents(ctx, req)
	if err != nil || bookmark != "" || !reflect.DeepEqual(eventTypes, []models.EventType{"device.create", "certificate.create"}) {
		t.Fatalf("event pages=%v bookmark=%q error=%v", eventTypes, bookmark, err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(count int) {
			defer wg.Done()
			e := *latest
			e.EventType = "concurrent"
			e.TotalSeen = count
			_, err := events.InsertUpdateEvent(ctx, &e)
			results <- err
		}(i + 1)
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent event upsert: %v", err)
		}
	}
}
