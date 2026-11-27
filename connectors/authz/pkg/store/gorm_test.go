package store

import (
	"context"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/testutil"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGormPrincipalStore_UpdatePersistsZeroValues(t *testing.T) {
	container, err := testutil.RunEmpty()
	require.NoError(t, err)
	defer container.Cleanup()

	sqlDB, err := container.DB.DB()
	require.NoError(t, err)

	log := logrus.NewEntry(logrus.New())
	log.Logger.SetLevel(logrus.ErrorLevel)
	require.NoError(t, RunMigrationsForProvider(sqlDB, "", testutil.StorageProvider(), log))

	s, err := NewGormPrincipalStore(container.DB)
	require.NoError(t, err)

	ctx := context.Background()
	principal := &models.Principal{
		ID:          "user-1",
		Name:        "John Doe",
		Description: "Before update",
		Type:        "oidc",
		AuthConfig:  models.AuthConfig{"claims": []any{}},
		Active:      true,
	}

	require.NoError(t, s.Create(ctx, principal))

	principal.Description = ""
	principal.Active = false
	require.NoError(t, s.Update(ctx, principal))

	retrieved, err := s.Get(ctx, "user-1")
	require.NoError(t, err)
	assert.Empty(t, retrieved.Description)
	assert.False(t, retrieved.Active)
}

func TestGormPrincipalStore_CreateRequiresType(t *testing.T) {
	container, err := testutil.RunEmpty()
	require.NoError(t, err)
	defer container.Cleanup()

	sqlDB, err := container.DB.DB()
	require.NoError(t, err)

	log := logrus.NewEntry(logrus.New())
	log.Logger.SetLevel(logrus.ErrorLevel)
	require.NoError(t, RunMigrationsForProvider(sqlDB, "", testutil.StorageProvider(), log))

	s, err := NewGormPrincipalStore(container.DB)
	require.NoError(t, err)

	ctx := context.Background()
	err = s.Create(ctx, &models.Principal{ID: "no-type", Name: "John Doe", Active: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "principal type is required")

	_, err = s.Get(ctx, "no-type")
	assert.Error(t, err, "a principal without type must not be stored")
}
