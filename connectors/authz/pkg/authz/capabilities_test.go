package authz

import (
	"context"
	"testing"

	"github.com/lamassuiot/authz/pkg/models"
	"github.com/lamassuiot/authz/pkg/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gocloud.dev/blob"
	_ "gocloud.dev/blob/fileblob"
	"gorm.io/gorm"
)

// ---------------------------------------------------------------------------
// Unit tests – MergeGlobalCapabilities
// ---------------------------------------------------------------------------

func TestMergeGlobalCapabilities(t *testing.T) {
	dst := GlobalCapabilities{
		"iot.public.device": {"create"},
	}
	src := GlobalCapabilities{
		"iot.public.device":  {"create", "list"}, // "create" is a duplicate
		"iot.public.gateway": {"list"},
	}

	MergeGlobalCapabilities(dst, src)

	assert.ElementsMatch(t, []string{"create", "list"}, dst["iot.public.device"])
	assert.ElementsMatch(t, []string{"list"}, dst["iot.public.gateway"])
}

// ---------------------------------------------------------------------------
// GetGlobalCapabilities – policy-level tests
// ---------------------------------------------------------------------------

func setupIoTEngine(t *testing.T, db *gorm.DB) *Engine {
	t.Helper()
	engine, err := NewEngine(
		map[string]*gorm.DB{"iot": db},
		map[string]string{"iot": "../../examples/iot/schemas.json"},
	)
	require.NoError(t, err)
	return engine
}

func TestGetGlobalCapabilities_PolicyWithGlobalActions(t *testing.T) {
	postgres, err := testutil.RunPostgresWithMigration("testdata/init.sql")
	require.NoError(t, err)
	defer postgres.Cleanup()

	engine := setupIoTEngine(t, postgres.DB)

	// "write" and "list" are global actions in the IoT schema for organization.
	policy := &models.Policy{
		ID:   "global-policy",
		Name: "Global Policy",
		Rules: []*models.Rule{
			{
				Namespace:  "iot",
				SchemaName: "public",
				EntityType: "organization",
				Actions:    []string{"read", "write", "list"},
			},
		},
	}

	registry := NewPolicyRegistry()
	require.NoError(t, registry.AddPolicy(policy))

	gc, err := engine.GetGlobalCapabilities(registry)
	require.NoError(t, err)

	// Only global actions should be returned.
	assert.ElementsMatch(t, []string{"write", "list"}, gc["iot.public.organization"],
		"global capabilities should include only globalActions from the schema")

	// Atomic actions must NOT appear.
	for _, action := range gc["iot.public.organization"] {
		assert.NotEqual(t, "read", action, "read is an atomic action and must not appear in global capabilities")
		assert.NotEqual(t, "delete", action)
	}
}

func TestGetGlobalCapabilities_PolicyWithOnlyAtomicActions(t *testing.T) {
	postgres, err := testutil.RunPostgresWithMigration("testdata/init.sql")
	require.NoError(t, err)
	defer postgres.Cleanup()

	engine := setupIoTEngine(t, postgres.DB)

	// Only atomic actions granted – global capabilities should be empty.
	policy := &models.Policy{
		ID:   "atomic-only",
		Name: "Atomic Only",
		Rules: []*models.Rule{
			{
				Namespace:    "iot",
				SchemaName:   "public",
				EntityType:   "organization",
				Actions:      []string{"read", "delete"},
				DirectGrants: []string{"org-1"},
			},
		},
	}

	registry := NewPolicyRegistry()
	require.NoError(t, registry.AddPolicy(policy))

	gc, err := engine.GetGlobalCapabilities(registry)
	require.NoError(t, err)

	// Nothing under "iot.public.organization" because no global action is granted.
	assert.Empty(t, gc["iot.public.organization"],
		"no global actions should be returned when policy only grants atomic actions")
}

func TestGetGlobalCapabilities_WildcardActionsIncludesGlobalSubset(t *testing.T) {
	postgres, err := testutil.RunPostgresWithMigration("testdata/init.sql")
	require.NoError(t, err)
	defer postgres.Cleanup()

	engine := setupIoTEngine(t, postgres.DB)

	// Wildcard "*" expands to all actions (atomic + global) – only global should appear.
	policy := &models.Policy{
		ID:   "wildcard-policy",
		Name: "Wildcard Policy",
		Rules: []*models.Rule{
			{
				Namespace:    "iot",
				SchemaName:   "public",
				EntityType:   "organization",
				Actions:      []string{"*"},
				DirectGrants: []string{"*"},
			},
		},
	}

	registry := NewPolicyRegistry()
	require.NoError(t, registry.AddPolicy(policy))

	gc, err := engine.GetGlobalCapabilities(registry)
	require.NoError(t, err)

	assert.Contains(t, gc["iot.public.organization"], "write")
	assert.Contains(t, gc["iot.public.organization"], "list")
}

func TestGetGlobalCapabilities_MultipleEntityTypes(t *testing.T) {
	postgres, err := testutil.RunPostgresWithMigration("testdata/init.sql")
	require.NoError(t, err)
	defer postgres.Cleanup()

	engine := setupIoTEngine(t, postgres.DB)

	policy := &models.Policy{
		ID:   "multi-entity",
		Name: "Multi Entity",
		Rules: []*models.Rule{
			{
				Namespace:  "iot",
				SchemaName: "public",
				EntityType: "organization",
				Actions:    []string{"list"},
			},
			{
				Namespace:  "iot",
				SchemaName: "public",
				EntityType: "gateway",
				Actions:    []string{"write", "list"},
			},
		},
	}

	registry := NewPolicyRegistry()
	require.NoError(t, registry.AddPolicy(policy))

	gc, err := engine.GetGlobalCapabilities(registry)
	require.NoError(t, err)

	assert.Contains(t, gc["iot.public.organization"], "list")
	assert.ElementsMatch(t, []string{"write", "list"}, gc["iot.public.gateway"])
}

// ---------------------------------------------------------------------------
// GetEntityCapabilities – policy-level tests
// ---------------------------------------------------------------------------

func TestGetEntityCapabilities_DirectGrants(t *testing.T) {
	postgres, err := testutil.RunPostgresWithMigration("testdata/init.sql")
	require.NoError(t, err)
	defer postgres.Cleanup()

	engine := setupIoTEngine(t, postgres.DB)

	policy := &models.Policy{
		ID:   "entity-policy",
		Name: "Entity Policy",
		Rules: []*models.Rule{
			{
				Namespace:    "iot",
				SchemaName:   "public",
				EntityType:   "organization",
				Actions:      []string{"read", "delete", "write", "list"},
				DirectGrants: []string{"org-1"},
			},
		},
	}

	registry := NewPolicyRegistry()
	require.NoError(t, registry.AddPolicy(policy))

	ec, err := engine.GetEntityCapabilities(registry, "iot", "public", "organization", map[string]string{"id": "org-1"})
	require.NoError(t, err)
	require.NotNil(t, ec)

	assert.Equal(t, "public", ec.SchemaName)
	assert.Equal(t, "organization", ec.EntityType)
	assert.Equal(t, map[string]string{"id": "org-1"}, ec.EntityKey)

	// Only atomic actions should appear (read, delete for organization).
	assert.Contains(t, ec.Actions, "read")
	assert.Contains(t, ec.Actions, "delete")

	// Global actions must NOT appear.
	for _, action := range ec.Actions {
		assert.NotEqual(t, "write", action, "write is a global action and must not appear in entity capabilities")
		assert.NotEqual(t, "list", action)
	}
}

func TestGetEntityCapabilities_NoAccess(t *testing.T) {
	postgres, err := testutil.RunPostgresWithMigration("testdata/init.sql")
	require.NoError(t, err)
	defer postgres.Cleanup()

	engine := setupIoTEngine(t, postgres.DB)

	// Policy grants only "org-2", not "org-99".
	policy := &models.Policy{
		ID:   "no-access-policy",
		Name: "No Access",
		Rules: []*models.Rule{
			{
				Namespace:    "iot",
				SchemaName:   "public",
				EntityType:   "organization",
				Actions:      []string{"read"},
				DirectGrants: []string{"org-2"},
			},
		},
	}

	registry := NewPolicyRegistry()
	require.NoError(t, registry.AddPolicy(policy))

	ec, err := engine.GetEntityCapabilities(registry, "iot", "public", "organization", map[string]string{"id": "org-99"})
	require.NoError(t, err)
	require.NotNil(t, ec)

	// No access – empty actions slice, never a 404.
	assert.Empty(t, ec.Actions)
}

func TestGetEntityCapabilities_UnknownSchema(t *testing.T) {
	postgres, err := testutil.RunPostgresWithMigration("testdata/init.sql")
	require.NoError(t, err)
	defer postgres.Cleanup()

	engine := setupIoTEngine(t, postgres.DB)

	registry := NewPolicyRegistry()

	_, err = engine.GetEntityCapabilities(registry, "nonexistent", "nonexistent", "organisation", map[string]string{"id": "org-1"})
	assert.Error(t, err, "should return an error for unknown schema/entity type")
}

// ---------------------------------------------------------------------------
// GetGlobalCapabilitiesForPrincipal
// ---------------------------------------------------------------------------

func TestGetGlobalCapabilitiesForPrincipal(t *testing.T) {
	postgres, err := testutil.RunPostgresWithMigration("testdata/init.sql")
	require.NoError(t, err)
	defer postgres.Cleanup()

	db := postgres.DB
	engine := setupIoTEngine(t, db)

	principalManager, err := NewPrincipalManager(db, nil)
	require.NoError(t, err)

	tempDir := t.TempDir()
	bucket, err := blob.OpenBucket(context.Background(), "file://"+tempDir)
	require.NoError(t, err)
	defer bucket.Close()

	policyManager := NewPolicyManager(bucket)

	policy := &models.Policy{
		ID:   "principal-policy",
		Name: "Principal Policy",
		Rules: []*models.Rule{
			{
				Namespace:  "iot",
				SchemaName: "public",
				EntityType: "organization",
				Actions:    []string{"read", "write", "list"},
			},
		},
	}
	require.NoError(t, policyManager.CreatePolicy(context.Background(), policy))

	principal := &models.Principal{
		ID:     "user-global",
		Name:   "Global User",
		Type:   "oidc",
		Active: true,
		AuthConfig: models.AuthConfig{
			"issuer": "https://example.com",
		},
	}
	require.NoError(t, principalManager.CreatePrincipal(principal))
	require.NoError(t, principalManager.GrantPolicy("user-global", "principal-policy", "admin"))

	gc, err := engine.GetGlobalCapabilitiesForPrincipal(principalManager, policyManager, "user-global")
	require.NoError(t, err)

	assert.Contains(t, gc["iot.public.organization"], "write")
	assert.Contains(t, gc["iot.public.organization"], "list")
}
