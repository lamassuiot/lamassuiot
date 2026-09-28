package eventhandling

import (
	"errors"
	"sync"
)

var ErrConflictingEventReplay = errors.New("event replay conflicts with its original tenant scope")

type EventDeliveryIdentity struct {
	EventID        string
	TenantID       string
	OrganizationID string
	PayloadHash    string
}

type EventDeduplicator struct {
	mu       sync.Mutex
	identity map[string]EventDeliveryIdentity
}

func NewEventDeduplicator() *EventDeduplicator {
	return &EventDeduplicator{identity: make(map[string]EventDeliveryIdentity)}
}

// Begin returns true only for the first delivery of an event ID.
// A reused ID must carry the same tenant, organization, and payload identity.
func (d *EventDeduplicator) Begin(identity EventDeliveryIdentity) (bool, error) {
	if identity.EventID == "" || identity.TenantID == "" || identity.OrganizationID == "" || identity.PayloadHash == "" {
		return false, ErrConflictingEventReplay
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	previous, exists := d.identity[identity.EventID]
	if !exists {
		d.identity[identity.EventID] = identity
		return true, nil
	}
	if previous != identity {
		return false, ErrConflictingEventReplay
	}
	return false, nil
}
