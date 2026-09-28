package postgres

import (
	"context"
	"errors"
	"testing"

	core "github.com/lamassuiot/lamassuiot/core/v3"
	postgrestest "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/test"
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
