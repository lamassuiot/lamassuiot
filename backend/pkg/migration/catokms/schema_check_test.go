package catokms

import (
	"context"
	"testing"

	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	postgres_test "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/test"
	"github.com/stretchr/testify/require"
)

// The tool tells the kms schema the key identity migration leaves, which the KMS repository needs, from an earlier one,
// where it writes the columns of 3.8 itself.
func TestHasKeyIdentity(t *testing.T) {
	cleanup, cfg, err := postgres_test.RunPostgresDocker(map[string]string{postgres.KMS_SCHEMA: ""}, false)
	require.NoError(t, err)
	defer func() { _ = cleanup() }()

	logger := helpers.SetupLogger(cconfig.Info, "test", "test")
	db, err := postgres.CreatePostgresDBConnection(logger, *cfg, postgres.KMS_SCHEMA)
	require.NoError(t, err)
	migrator := postgres.NewMigrator(logger, db)

	const beforeKeyIdentity = int64(20261030120100)
	_, err = migrator.Goose.UpTo(context.Background(), beforeKeyIdentity)
	require.NoError(t, err)

	migrated, err := hasKeyIdentity(db)
	require.NoError(t, err)
	require.False(t, migrated, "a kms schema without the key identity migration")

	_, err = migrator.Goose.Up(context.Background())
	require.NoError(t, err)
	migrated, err = hasKeyIdentity(db)
	require.NoError(t, err)
	require.True(t, migrated, "a migrated kms schema")
}
