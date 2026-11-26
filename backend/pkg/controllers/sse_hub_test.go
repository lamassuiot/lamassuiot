package controllers

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func newTestHub(opts DeviceEventSSEHubOptions) *DeviceEventSSEHub {
	return NewDeviceEventSSEHub(logrus.NewEntry(logrus.New()), opts)
}

func TestHubRefusesSubscribersAboveLimit(t *testing.T) {
	hub := newTestHub(DeviceEventSSEHubOptions{MaxSubscribers: 2})

	for _, id := range []string{"dev-1", "dev-2"} {
		if _, err := hub.Subscribe(id); err != nil {
			t.Fatalf("subscribe %s: unexpected error: %s", id, err)
		}
	}

	ch, err := hub.Subscribe("dev-3")
	if !errors.Is(err, ErrSSESubscriberLimit) {
		t.Fatalf("expected ErrSSESubscriberLimit. Got %v", err)
	}
	if ch != nil {
		t.Fatalf("expected nil channel when the limit is reached")
	}
}

func TestHubUnsubscribeFreesSlot(t *testing.T) {
	hub := newTestHub(DeviceEventSSEHubOptions{MaxSubscribers: 1})

	ch, err := hub.Subscribe("dev-1")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	hub.Unsubscribe("dev-1", ch)

	if _, err := hub.Subscribe("dev-1"); err != nil {
		t.Fatalf("expected the freed slot to be reusable. Got %v", err)
	}
}

func TestHubDoubleUnsubscribeDecrementsOnce(t *testing.T) {
	hub := newTestHub(DeviceEventSSEHubOptions{MaxSubscribers: 2})

	a, err := hub.Subscribe("dev-a")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if _, err := hub.Subscribe("dev-b"); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	hub.Unsubscribe("dev-a", a)
	hub.Unsubscribe("dev-a", a)

	if got := hub.subscriberCount(); got != 1 {
		t.Fatalf("expected 1 subscriber. Got %d", got)
	}
	if _, err := hub.Subscribe("dev-c"); err != nil {
		t.Fatalf("expected one free slot. Got %v", err)
	}
	if _, err := hub.Subscribe("dev-d"); !errors.Is(err, ErrSSESubscriberLimit) {
		t.Fatalf("expected ErrSSESubscriberLimit. Got %v", err)
	}
}

func TestHubDefaults(t *testing.T) {
	hub := newTestHub(DeviceEventSSEHubOptions{})

	if got := hub.MaxStreamDuration(); got != 10*time.Minute {
		t.Fatalf("expected default stream duration of 10m. Got %s", got)
	}

	for i := 0; i < DefaultSSEMaxSubscribers; i++ {
		if _, err := hub.Subscribe(fmt.Sprintf("dev-%d", i)); err != nil {
			t.Fatalf("subscribe %d: unexpected error: %s", i+1, err)
		}
	}
	if _, err := hub.Subscribe("one-too-many"); !errors.Is(err, ErrSSESubscriberLimit) {
		t.Fatalf("expected ErrSSESubscriberLimit at subscriber %d. Got %v", DefaultSSEMaxSubscribers+1, err)
	}
}
