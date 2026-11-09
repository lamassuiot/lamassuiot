package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	postgrestest "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/test"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestWithTenantTransactionScopesSetting(t *testing.T) {
	_, suite := postgrestest.BeforeSuite([]string{"ca"}, false)
	defer suite.AfterSuite()

	ctx := core.WithTenantContext(context.Background(), core.TenantContext{
		OrganizationID: "org-test",
		TenantID:       "00000000-0000-0000-0000-000000000002",
		ActorID:        "actor-test",
		ActorType:      "user",
		CorrelationID:  "correlation-test",
		Source:         "rls-test",
		TenantStatus:   core.TenantActive,
		Validated:      true,
	})

	db := suite.DB["ca"]
	var inside string
	err := WithTenantTransaction(ctx, db, func(tx *gorm.DB) error {
		return tx.Raw("SELECT current_setting('app.tenant_id', true)").Scan(&inside).Error
	})
	require.NoError(t, err)
	require.Equal(t, "00000000-0000-0000-0000-000000000002", inside)

	var after string
	require.NoError(t, db.Raw("SELECT current_setting('app.tenant_id', true)").Scan(&after).Error)
	require.Empty(t, after)

	err = WithTenantTransaction(context.Background(), db, func(tx *gorm.DB) error {
		return nil
	})
	require.Error(t, err)
	require.True(t, errors.Is(err, core.ErrTenantContextRequired))
}

func TestWithTenantIDTransactionUsesGivenTenant(t *testing.T) {
	_, suite := postgrestest.BeforeSuite([]string{"ca"}, false)
	defer suite.AfterSuite()

	db := suite.DB["ca"]
	var inside string
	err := withTenantIDTransaction(context.Background(), db, models.DefaultTenantID, func(tx *gorm.DB) error {
		return tx.Raw("SELECT current_setting('app.tenant_id', true)").Scan(&inside).Error
	})
	require.NoError(t, err)
	require.Equal(t, models.DefaultTenantID, inside)

	executed := false
	err = withTenantIDTransaction(context.Background(), db, "", func(tx *gorm.DB) error {
		executed = true
		return nil
	})
	require.Error(t, err)
	require.False(t, executed)
}
