package eventhandling

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEventDeduplicatorPreservesTenantScope(t *testing.T) {
	deduplicator := NewEventDeduplicator()
	identity := EventDeliveryIdentity{
		EventID:        "event-1",
		TenantID:       "tenant-a",
		OrganizationID: "org-a",
		PayloadHash:    "hash-a",
	}

	first, err := deduplicator.Begin(identity)
	assert.NoError(t, err)
	assert.True(t, first)

	retry, err := deduplicator.Begin(identity)
	assert.NoError(t, err)
	assert.False(t, retry)

	conflict := identity
	conflict.TenantID = "tenant-b"
	accepted, err := deduplicator.Begin(conflict)
	assert.ErrorIs(t, err, ErrConflictingEventReplay)
	assert.False(t, accepted)
}
