package postgres

import (
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	postgrestest "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKMSSelectExistsByAliasTenantIsolation guards against a regression of a real bug found
// while implementing generic tenant scoping: SelectExistsByAlias used to run a raw,
// unscoped query directly against the kms_keys table, so any tenant could discover another
// tenant's key by alias. It must now behave like every other tenant-scoped lookup.
func TestKMSSelectExistsByAliasTenantIsolation(t *testing.T) {
	logger := helpers.SetupLogger(config.Info, "test", "kms-repo-tenant-isolation")

	_, suite := postgrestest.BeforeSuite([]string{"kms"}, false)
	defer suite.AfterSuite()
	suite.BeforeEach()

	db := suite.DB["kms"]

	migrator := NewMigrator(logger, db)
	migrator.MigrateToLatest()

	repo, err := NewKMSPostgresRepository(logger, db)
	require.NoError(t, err)

	tenantA := deviceGroupsTenantContext("00000000-0000-0000-0000-0000000000a1")
	tenantB := deviceGroupsTenantContext("00000000-0000-0000-0000-0000000000b2")

	key := &models.Key{
		KeyID:      "kms-key-tenant-a",
		Name:       "tenant-a-key",
		Aliases:    []string{"shared-alias"},
		EngineID:   "filesystem-1",
		Algorithm:  "RSA",
		Size:       4096,
		CreationTS: time.Now(),
		Tags:       []string{},
		Metadata:   map[string]any{},
	}

	_, err = repo.Insert(tenantA, key)
	require.NoError(t, err)

	// No context: fails closed.
	_, _, err = repo.SelectExistsByAlias(t.Context(), "shared-alias")
	assert.Error(t, err)

	// Owning tenant finds it.
	found, got, err := repo.SelectExistsByAlias(tenantA, "shared-alias")
	require.NoError(t, err)
	assert.True(t, found)
	require.NotNil(t, got)
	assert.Equal(t, "kms-key-tenant-a", got.KeyID)

	// A different tenant must not discover the alias, even though it exists.
	found, got, err = repo.SelectExistsByAlias(tenantB, "shared-alias")
	require.NoError(t, err)
	assert.False(t, found)
	assert.Nil(t, got)
}
