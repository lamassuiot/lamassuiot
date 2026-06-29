package service

import (
	"io"
	"testing"

	"github.com/lamassuiot/lamassuiot/connectors/authz/v3/pkg/store"
	"github.com/lamassuiot/lamassuiot/connectors/authz/v3/pkg/testutil"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// setupDBWithAuthzMigrations starts a Postgres container, mounts initSQLPath as the
// Docker init script (for domain tables), then runs goose authz migrations so the
// principals/principal_policies/policies tables exist before the test creates any stores.
// Cleanup is registered via t.Cleanup — no explicit defer needed in the caller.
func setupDBWithAuthzMigrations(t *testing.T, initSQLPath string) *gorm.DB {
	t.Helper()

	container, err := testutil.RunPostgresWithMigration(initSQLPath)
	require.NoError(t, err)
	t.Cleanup(func() { container.Cleanup() })

	sqlDB, err := container.DB.DB()
	require.NoError(t, err)

	log := logrus.NewEntry(logrus.New())
	log.Logger.SetOutput(io.Discard)
	require.NoError(t, store.RunMigrations(sqlDB, log))

	return container.DB
}
