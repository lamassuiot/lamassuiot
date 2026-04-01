package controllers

import (
	"encoding/json"
	"sync"

	"github.com/sirupsen/logrus"
)

// DeviceSSEMessage represents a generic SSE message for a device.
// EventType is the CloudEvent type (e.g. "device.create", "device.status.update").
// Data is the raw JSON payload of the event.
type DeviceSSEMessage struct {
	EventType string          `json:"event_type"`
	Data      json.RawMessage `json:"data"`
}

// DeviceEventSSEHub is an in-memory pub/sub broker that fans out device events
// to SSE clients. Each SSE client registers a channel keyed by device ID.
// The hub is fed by the AMQP event bus subscription so it works across instances.
type DeviceEventSSEHub struct {
	mu          sync.RWMutex
	subscribers map[string]map[chan string]struct{} // deviceID → set of SSE channels
	logger      *logrus.Entry
}

func NewDeviceEventSSEHub(logger *logrus.Entry) *DeviceEventSSEHub {
	return &DeviceEventSSEHub{
		subscribers: make(map[string]map[chan string]struct{}),
		logger:      logger,
	}
}

// Subscribe registers a new SSE listener for a given device ID.
// Returns a channel that will receive JSON-encoded DeviceSSEMessage strings.
func (h *DeviceEventSSEHub) Subscribe(deviceID string) chan string {
	h.mu.Lock()
	defer h.mu.Unlock()

	ch := make(chan string, 64)
	if _, ok := h.subscribers[deviceID]; !ok {
		h.subscribers[deviceID] = make(map[chan string]struct{})
	}
	h.subscribers[deviceID][ch] = struct{}{}
	h.logger.Debugf("SSE client subscribed for device %s (total: %d)", deviceID, len(h.subscribers[deviceID]))
	return ch
}

// Unsubscribe removes an SSE listener and closes its channel.
func (h *DeviceEventSSEHub) Unsubscribe(deviceID string, ch chan string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if subs, ok := h.subscribers[deviceID]; ok {
		delete(subs, ch)
		close(ch)
		if len(subs) == 0 {
			delete(h.subscribers, deviceID)
		}
		h.logger.Debugf("SSE client unsubscribed for device %s", deviceID)
	}
}

// Publish sends a device event to all SSE listeners for the given device ID.
// The payload is any serializable object; it will be wrapped in a DeviceSSEMessage with the event type.
func (h *DeviceEventSSEHub) Publish(deviceID string, eventType string, payload interface{}) {
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
