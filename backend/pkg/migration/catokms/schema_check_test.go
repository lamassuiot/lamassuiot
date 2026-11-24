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

// The tool registers every key with its digest, so it needs the kms schema the key identity migration leaves. It does
// not migrate anything itself: against an older schema it has to stop with a message that says what to run first,
// instead of failing on every insert with a SQL error.
func TestCheckKMSSchema(t *testing.T) {
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

	err = checkKMSSchema(db)
	require.Error(t, err, "a kms schema without the key identity migration is refused")
	require.Contains(t, err.Error(), "kms schema")
	require.Contains(t, err.Error(), "goose-lamassu")

	_, err = migrator.Goose.Up(context.Background())
	require.NoError(t, err)
	require.NoError(t, checkKMSSchema(db), "a migrated kms schema is accepted")
}
