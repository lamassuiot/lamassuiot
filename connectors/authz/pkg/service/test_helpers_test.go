package service

import (
	"io"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/store"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/testutil"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// setupDBWithAuthzMigrations starts the selected database, creates its domain
// fixture, then runs Authz migrations before the test creates any stores.
// Cleanup is registered via t.Cleanup — no explicit defer needed in the caller.
func setupDBWithAuthzMigrations(t *testing.T, initSQLPath string) *gorm.DB {
	t.Helper()

	container, err := testutil.RunWithMigration(initSQLPath)
	require.NoError(t, err)
	t.Cleanup(func() { container.Cleanup() })

	sqlDB, err := container.DB.DB()
	require.NoError(t, err)

	log := logrus.NewEntry(logrus.New())
	log.Logger.SetOutput(io.Discard)
	require.NoError(t, store.RunMigrationsForProvider(sqlDB, "", testutil.StorageProvider(), log))

	return container.DB
}
