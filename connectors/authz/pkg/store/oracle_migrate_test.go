package store

import (
	"context"
	"errors"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/testutil"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOracleMigrationsRefuseToContinueAfterAFailure checks that an Authz
// Oracle migration that fails part-way is recorded as started, that the next
// run refuses to continue instead of retrying DDL Oracle may have committed,
// and that migrations complete once the version is recovered by hand.
func TestOracleMigrationsRefuseToContinueAfterAFailure(t *testing.T) {
	if testutil.StorageProvider() != "oracle" {
		t.Skip("Oracle-specific migration tracking")
	}
	container, err := testutil.RunEmpty()
	require.NoError(t, err)
	defer container.Cleanup()

	db, err := container.DB.DB()
	require.NoError(t, err)
	ctx := context.Background()
	log := logrus.NewEntry(logrus.New())
	log.Logger.SetLevel(logrus.ErrorLevel)

	// The first migration creates PRINCIPALS; an existing table makes it fail.
	_, err = db.ExecContext(ctx, "CREATE TABLE principals (id VARCHAR2(10))")
	require.NoError(t, err)

	err = RunMigrationsForProvider(db, "", "oracle", log)
	require.True(t, errors.Is(err, ErrInterruptedMigration), "first run error: %v", err)
	var applied int
	require.NoError(t, db.QueryRowContext(ctx, "SELECT is_applied FROM AUTHZ_SCHEMA_MIGRATIONS WHERE version_id = 1").Scan(&applied))
	assert.Equal(t, 0, applied, "the failed migration is recorded as started")

	err = RunMigrationsForProvider(db, "", "oracle", log)
	require.True(t, errors.Is(err, ErrInterruptedMigration), "second run error: %v", err)
	assert.Contains(t, err.Error(), "version 1 is recorded as started")

	// Manual recovery: undo the partial changes and clear the started record.
	_, err = db.ExecContext(ctx, "DROP TABLE principals")
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, "DELETE FROM AUTHZ_SCHEMA_MIGRATIONS WHERE version_id = 1 AND is_applied = 0")
	require.NoError(t, err)

	require.NoError(t, RunMigrationsForProvider(db, "", "oracle", log))
	var started, total int
	require.NoError(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM AUTHZ_SCHEMA_MIGRATIONS WHERE is_applied = 0").Scan(&started))
	require.NoError(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM AUTHZ_SCHEMA_MIGRATIONS WHERE version_id > 0").Scan(&total))
	assert.Zero(t, started)
	sources, err := embedMigrations.ReadDir("oracle_migrations")
	require.NoError(t, err)
	assert.Equal(t, len(sources), total, "every migration is recorded as applied")

	// A second run is a no-op.
	require.NoError(t, RunMigrationsForProvider(db, "", "oracle", log))
}
