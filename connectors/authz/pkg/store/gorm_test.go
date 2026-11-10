package store

import (
	"context"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/testutil"
	postgres "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pgdialector "gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestGormPrincipalStoreQualifiesTablesForRDSDataAPI(t *testing.T) {
	db, err := gorm.Open(pgdialector.Open(""), &gorm.Config{
		DisableAutomaticPing: true,
		DryRun:               true,
		NamingStrategy:       postgres.NewPostgresSchemaNamingStrategy("authz"),
	})
	require.NoError(t, err)

	store, err := NewGormPrincipalStore(db)
	require.NoError(t, err)
	assert.Equal(t, `"authz"."principals"`, store.principalTableExpr)
	assert.Equal(t, `"authz"."principal_policies"`, store.principalPoliciesTableExpr)
}

func TestGormPrincipalStore_UpdatePersistsZeroValues(t *testing.T) {
	container, err := testutil.RunPostgresEmpty()
	require.NoError(t, err)
	defer container.Cleanup()

	sqlDB, err := container.DB.DB()
	require.NoError(t, err)

	log := logrus.NewEntry(logrus.New())
	log.Logger.SetLevel(logrus.ErrorLevel)
	require.NoError(t, RunMigrations(sqlDB, "", log))

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
