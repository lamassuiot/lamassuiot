package postgres

import (
	"slices"
	"testing"

	lconfig "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/config"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrationRejectsRDSDataAPI(t *testing.T) {
	cfg := lconfig.PostgresPSEConfig{Transport: lconfig.PostgresTransportRDSDataAPI}
	logger := logrus.NewEntry(logrus.New())

	t.Run("single schema", func(t *testing.T) {
		require.ErrorContains(t, MigrateSchema(logger, cfg, CA_SCHEMA), "migrations require direct PostgreSQL")
	})
	t.Run("all schemas", func(t *testing.T) {
		require.ErrorContains(t, MigrateAllSchemas(logger, cfg), "migrations require direct PostgreSQL")
	})
}

// ca.certificates references kms.kms_keys, so the KMS schema is migrated first.
func TestMigrationSchemaOrderPutsKMSBeforeCA(t *testing.T) {
	order := MigrationSchemaOrder()
	kms, ca := slices.Index(order, KMS_SCHEMA), slices.Index(order, CA_SCHEMA)
	require.NotEqual(t, -1, kms)
	require.NotEqual(t, -1, ca)
	assert.Less(t, kms, ca)
}

func TestOrderForMigrationMovesDependenciesFirst(t *testing.T) {
	got := OrderForMigration([]string{"ca", "alerts", "kms", "authz", "va"})

	assert.Less(t, slices.Index(got, "kms"), slices.Index(got, "ca"))
	assert.ElementsMatch(t, []string{"ca", "alerts", "kms", "authz", "va"}, got, "no schema is added or lost, even the unknown ones")
}
