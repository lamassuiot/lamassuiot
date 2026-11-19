package upgradecheck

import (
	"context"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"github.com/stretchr/testify/require"
)

func TestCheckV38DatabaseAccepts38(t *testing.T) {
	cfg := runV38DB(t)
	require.NoError(t, CheckV38Database(context.Background(), NewEnv(testLogger, *cfg)))
}

func TestCheckV38DatabaseRejectsMigrated(t *testing.T) {
	cfg := runV38DB(t)
	require.NoError(t, postgres.MigrateAllSchemas(testLogger, *cfg))

	err := CheckV38Database(context.Background(), NewEnv(testLogger, *cfg))
	require.ErrorIs(t, err, ErrNotV38Database)
}
