package core

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTenantIDContextHelpers(t *testing.T) {
	t.Run("missing or empty tenant returns false and ErrMissingTenantID", func(t *testing.T) {
		id, ok := TenantIDFromContext(context.Background())
		assert.False(t, ok)
		assert.Empty(t, id)

		_, err := RequireTenantID(context.Background())
		assert.True(t, errors.Is(err, ErrMissingTenantID))

		ctxEmpty := WithTenantID(context.Background(), "   ")
		_, err = RequireTenantID(ctxEmpty)
		assert.True(t, errors.Is(err, ErrMissingTenantID))
	})

	t.Run("stores and retrieves trimmed tenant_id", func(t *testing.T) {
		ctx := WithTenantID(context.Background(), "  tenant-1  ")

		id, ok := TenantIDFromContext(ctx)
		assert.True(t, ok)
		assert.Equal(t, "tenant-1", id)

		reqID, err := RequireTenantID(ctx)
		require.NoError(t, err)
		assert.Equal(t, "tenant-1", reqID)
	})
}
