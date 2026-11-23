package postgres

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
