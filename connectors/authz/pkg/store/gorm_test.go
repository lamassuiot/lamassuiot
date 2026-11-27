package store

import (
	"context"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/testutil"
	authzsdk "github.com/lamassuiot/lamassuiot/v4/connectors/authz/sdk"
	authzgorm "github.com/lamassuiot/lamassuiot/v4/connectors/authz/sdk/gorm"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
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

// TestGormPrincipalStore_ListWithActiveAuthorizationFilter runs the GET /principals
// authorization filter on principals.active through the provider's Authz GORM
// plugin, as the Authz assembler registers it.
func TestGormPrincipalStore_ListWithActiveAuthorizationFilter(t *testing.T) {
	container, err := testutil.RunEmpty()
	require.NoError(t, err)
	defer container.Cleanup()

	sqlDB, err := container.DB.DB()
	require.NoError(t, err)

	log := logrus.NewEntry(logrus.New())
	log.Logger.SetLevel(logrus.ErrorLevel)
	require.NoError(t, RunMigrationsForProvider(sqlDB, "", testutil.StorageProvider(), log))

	var plugin gorm.Plugin = authzgorm.NewAuthzGormPlugin()
	if testutil.StorageProvider() == "oracle" {
		plugin = authzgorm.NewOracleAuthzGormPlugin()
	}
	require.NoError(t, container.DB.Use(plugin))

	s, err := NewGormPrincipalStore(container.DB)
	require.NoError(t, err)

	ctx := context.Background()
	for _, p := range []*models.Principal{
		{ID: "active-user", Name: "Active", Type: "oidc", Active: true},
		{ID: "inactive-user", Name: "Inactive", Type: "oidc", Active: true},
	} {
		require.NoError(t, s.Create(ctx, p))
	}
	require.NoError(t, s.SetActive(ctx, "inactive-user", false))

	for filter, want := range map[string]string{
		"true":    "active-user",
		"'false'": "inactive-user",
	} {
		authzCtx := context.WithValue(ctx, authzsdk.AuthzQueryKey, "SELECT * FROM principals WHERE principals.active = "+filter)
		principals, _, err := s.List(authzCtx, nil)
		require.NoError(t, err, "active = %s", filter)
		require.Len(t, principals, 1, "active = %s", filter)
		assert.Equal(t, want, principals[0].ID, "active = %s", filter)
	}
}

// TestGormPrincipalStore_ListWithDateOnlyFilter checks that date filters
// accept a date alone, as PostgreSQL's timestamp cast does, on both providers.
func TestGormPrincipalStore_ListWithDateOnlyFilter(t *testing.T) {
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
	require.NoError(t, s.Create(ctx, &models.Principal{ID: "dated-user", Name: "Dated", Type: "oidc", Active: true}))

	yesterday := time.Now().UTC().AddDate(0, 0, -1).Format(time.DateOnly)
	tomorrow := time.Now().UTC().AddDate(0, 0, 1).Format(time.DateOnly)
	for _, tc := range []struct {
		op    resources.FilterOperation
		value string
		want  int
	}{
		{resources.DateAfter, yesterday, 1},
		{resources.DateBefore, tomorrow, 1},
		{resources.DateAfter, tomorrow, 0},
	} {
		principals, _, err := s.List(ctx, &resources.QueryParameters{
			Filters: []resources.FilterOption{{Field: "created_at", FilterOperation: tc.op, Value: tc.value}},
		})
		require.NoError(t, err, "created_at op %d %s", tc.op, tc.value)
		assert.Len(t, principals, tc.want, "created_at op %d %s", tc.op, tc.value)
	}
}
