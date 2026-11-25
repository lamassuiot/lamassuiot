package controllers

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// DeviceSSEMessage represents a generic SSE message for a device.
// EventType is the CloudEvent type (e.g. "device.create", "device.status.update").
// Data is the raw JSON payload of the event.
type DeviceSSEMessage struct {
	EventType string          `json:"event_type"`
	Data      json.RawMessage `json:"data"`
}

// ErrSSESubscriberLimit is returned by Subscribe when the hub already serves its maximum number of SSE clients.
var ErrSSESubscriberLimit = errors.New("SSE subscriber limit reached")

const (
	// DefaultSSEMaxSubscribers is the subscriber limit used when DeviceEventSSEHubOptions.MaxSubscribers is 0.
	DefaultSSEMaxSubscribers = 1000
	// DefaultSSEMaxStreamDuration is the stream lifetime used when DeviceEventSSEHubOptions.MaxStreamDuration is 0.
	DefaultSSEMaxStreamDuration = 10 * time.Minute
)

// DeviceEventSSEHubOptions tunes the hub. A zero value selects the default for each field.
type DeviceEventSSEHubOptions struct {
	// MaxSubscribers bounds the SSE clients served at once, across all devices.
	MaxSubscribers int
	// MaxStreamDuration is how long a single SSE stream may stay open.
	MaxStreamDuration time.Duration
}

// DeviceEventSSEHub is an in-memory pub/sub broker that fans out device events
// to SSE clients. Each SSE client registers a channel keyed by device ID.
// The hub is fed by the AMQP event bus subscription so it works across instances.
type DeviceEventSSEHub struct {
	mu          sync.RWMutex
	subscribers map[string]map[chan string]struct{} // deviceID → set of SSE channels
	total       int                                 // registered channels across all devices, guarded by mu
	opts        DeviceEventSSEHubOptions
	logger      *logrus.Entry
}

func NewDeviceEventSSEHub(logger *logrus.Entry, opts DeviceEventSSEHubOptions) *DeviceEventSSEHub {
	if opts.MaxSubscribers == 0 {
		opts.MaxSubscribers = DefaultSSEMaxSubscribers
	}
	if opts.MaxStreamDuration == 0 {
		opts.MaxStreamDuration = DefaultSSEMaxStreamDuration
	}
	return &DeviceEventSSEHub{
		subscribers: make(map[string]map[chan string]struct{}),
		opts:        opts,
		logger:      logger,
	}
}

// MaxStreamDuration returns how long a single SSE stream may stay open.
func (h *DeviceEventSSEHub) MaxStreamDuration() time.Duration {
	return h.opts.MaxStreamDuration
}

// subscriberCount returns the number of registered channels across all devices.
func (h *DeviceEventSSEHub) subscriberCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.total
}

// Subscribe registers a new SSE listener for a given device ID.
// Returns a channel that will receive JSON-encoded DeviceSSEMessage strings, or ErrSSESubscriberLimit
// when the hub already serves its maximum number of clients.
func (h *DeviceEventSSEHub) Subscribe(deviceID string) (chan string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.total >= h.opts.MaxSubscribers {
		return nil, ErrSSESubscriberLimit
	}

	ch := make(chan string, 64)
	if _, ok := h.subscribers[deviceID]; !ok {
		h.subscribers[deviceID] = make(map[chan string]struct{})
	}
	h.subscribers[deviceID][ch] = struct{}{}
	h.total++
	h.logger.Debugf("SSE client subscribed for device %s (device: %d, total: %d)", deviceID, len(h.subscribers[deviceID]), h.total)
	return ch, nil
}

// Unsubscribe removes an SSE listener and closes its channel.
// Only closes ch if it is still registered, making the call idempotent and
// safe against a double-close panic if called more than once for the same channel.
func (h *DeviceEventSSEHub) Unsubscribe(deviceID string, ch chan string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if subs, ok := h.subscribers[deviceID]; ok {
		if _, registered := subs[ch]; registered {
			delete(subs, ch)
			h.total--
			if len(subs) == 0 {
				delete(h.subscribers, deviceID)
			}
			h.logger.Debugf("SSE client unsubscribed for device %s", deviceID)
			close(ch)
		}
	}
}

// Publish sends a device event to all SSE listeners for the given device ID.
// The payload is any serializable object; it will be wrapped in a DeviceSSEMessage with the event type.
func (h *DeviceEventSSEHub) Publish(deviceID string, eventType string, payload any) {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		h.logger.Errorf("could not marshal SSE payload for device %s: %s", deviceID, err)
		return
	}

	msg := DeviceSSEMessage{
		EventType: eventType,
		Data:      payloadBytes,
	}

	data, err := json.Marshal(msg)
	if err != nil {
		h.logger.Errorf("could not marshal SSE message for device %s: %s", deviceID, err)
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	subs, ok := h.subscribers[deviceID]
	if !ok {
		return
	}

	for ch := range subs {
		select {
		case ch <- string(data):
		default:
			h.logger.Warnf("SSE channel full for device %s, dropping event", deviceID)
		}
	}
}
