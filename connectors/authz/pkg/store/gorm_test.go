package store

import (
	"context"
	"testing"

	"github.com/lamassuiot/authz/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestGormPrincipalStore_UpdatePersistsZeroValues(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	store, err := NewGormPrincipalStore(db)
	require.NoError(t, err)

	ctx := context.Background()
	principal := &models.Principal{
		ID:          "user-1",
		Name:        "John Doe",
		Description: "Before update",
		Type:        "oidc",
		AuthConfig:  models.AuthConfig{"claims": []interface{}{}},
		Active:      true,
	}

	require.NoError(t, store.Create(ctx, principal))

	principal.Description = ""
	principal.Active = false
	require.NoError(t, store.Update(ctx, principal))

	retrieved, err := store.Get(ctx, "user-1")
	require.NoError(t, err)
	assert.Empty(t, retrieved.Description)
	assert.False(t, retrieved.Active)
}
