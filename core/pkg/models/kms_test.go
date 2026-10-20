package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyBoundResources(t *testing.T) {
	cert := KMSBindResource{ResourceType: KMSBindResourceTypeCertificate, ResourceID: "aa-01"}

	// Read back from storage, or as set by the KMS before storing it.
	for name, value := range map[string]any{
		"Stored": []any{map[string]any{"resource_type": "certificate", "resource_id": "aa-01"}},
		"Typed":  []KMSBindResource{cert},
	} {
		t.Run(name, func(t *testing.T) {
			key := Key{Metadata: map[string]any{KMSBindResourceKey: value}}
			bound, err := key.BoundResources()
			require.NoError(t, err)
			assert.Equal(t, []KMSBindResource{cert}, bound)
		})
	}

	t.Run("Absent", func(t *testing.T) {
		bound, err := (&Key{Metadata: map[string]any{}}).BoundResources()
		require.NoError(t, err)
		assert.Empty(t, bound)
	})

	// Only a list is a valid value: Lamassu never writes another shape.
	for name, value := range map[string]any{
		"SingleObject": map[string]any{"resource_type": "certificate", "resource_id": "aa-01"},
		"JSONString":   `[{"resource_type":"certificate","resource_id":"aa-01"}]`,
		"Number":       42,
		"ListOfNumber": []any{1},
	} {
		t.Run("Unreadable"+name, func(t *testing.T) {
			_, err := (&Key{Metadata: map[string]any{KMSBindResourceKey: value}}).BoundResources()
			assert.Error(t, err)
		})
	}
}
