package authz

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lamassuiot/authz/pkg/models"
	"github.com/lamassuiot/authz/pkg/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestGetGlobalCapabilities_EndToEnd_JWT ensures the full flow of matching a JWT to a
// principal and deriving global capabilities works correctly.
func TestGetGlobalCapabilities_EndToEnd_JWT(t *testing.T) {
	postgres, err := testutil.RunPostgresWithMigration("testdata/init.sql")
	require.NoError(t, err)
	defer postgres.Cleanup()

	db := postgres.DB

	// test-schema.json has organization with atomicActions=[read,delete], globalActions=[]
	engine, err := NewEngine(
		map[string]*gorm.DB{"test": db},
		map[string]string{"test": "testdata/test-schema.json"},
	)
	require.NoError(t, err)

	principalManager, err := NewPrincipalManager(db, nil)
	require.NoError(t, err)

	// Build an in-memory policy registry (no blob store needed for this test).
	policyRegistry := NewPolicyRegistry()
	policy := &models.Policy{
		ID:   "test-policy",
		Name: "Test Policy",
		Rules: []*models.Rule{
			{
				Namespace:    "test",
				SchemaName:   "public",
				EntityType:   "organization",
				Actions:      []string{"read", "delete"},
				DirectGrants: []string{"org-1"},
			},
		},
	}
	require.NoError(t, policyRegistry.AddPolicy(policy))

	principal := &models.Principal{
		ID:   "user-123",
		Name: "John Doe",
		Type: "oidc",
		AuthConfig: models.AuthConfig{
			"claims": []interface{}{
				map[string]interface{}{
					"claim":    "sub",
					"operator": "equals",
					"value":    "user-123",
				},
			},
		},
		Active: true,
	}
	require.NoError(t, principalManager.CreatePrincipal(principal))

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "user-123",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	matchedIDs, err := principalManager.MatchPrincipals(context.Background(), tokenString, "oidc")
	require.NoError(t, err)
	require.NotEmpty(t, matchedIDs)
	assert.Equal(t, "user-123", matchedIDs[0])

	// test-schema organization has no globalActions, so global capabilities must be empty.
	gc, err := engine.GetGlobalCapabilities(policyRegistry)
	require.NoError(t, err)
	assert.Empty(t, gc["public.organization"],
		"test schema defines no globalActions for organization, so result must be empty")

	t.Logf("Matched JWT to principal %s; global capabilities verified empty as expected", matchedIDs[0])
}

// TestGetEntityCapabilities_EndToEnd_JWT ensures the full flow of matching a JWT and then
// querying atomic actions for a specific entity works correctly.
func TestGetEntityCapabilities_EndToEnd_JWT(t *testing.T) {
	postgres, err := testutil.RunPostgresWithMigration("testdata/init.sql")
	require.NoError(t, err)
	defer postgres.Cleanup()

	db := postgres.DB

	engine, err := NewEngine(
		map[string]*gorm.DB{"test": db},
		map[string]string{"test": "testdata/test-schema.json"},
	)
	require.NoError(t, err)

	principalManager, err := NewPrincipalManager(db, nil)
	require.NoError(t, err)

	// Policy: grants read+delete on org-1.
	policyRegistry := NewPolicyRegistry()
	policy := &models.Policy{
		ID:   "entity-policy",
		Name: "Entity Policy",
		Rules: []*models.Rule{
			{
				Namespace:    "test",
				SchemaName:   "public",
				EntityType:   "organization",
				Actions:      []string{"read", "delete"},
				DirectGrants: []string{"org-1"},
			},
		},
	}
	require.NoError(t, policyRegistry.AddPolicy(policy))

	principal := &models.Principal{
		ID:   "user-456",
		Name: "Jane Doe",
		Type: "oidc",
		AuthConfig: models.AuthConfig{
			"claims": []interface{}{
				map[string]interface{}{
					"claim":    "sub",
					"operator": "equals",
					"value":    "user-456",
				},
			},
		},
		Active: true,
	}
	require.NoError(t, principalManager.CreatePrincipal(principal))

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "user-456",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	matchedIDs, err := principalManager.MatchPrincipals(context.Background(), tokenString, "oidc")
	require.NoError(t, err)
	require.NotEmpty(t, matchedIDs)

	// Granted entity org-1 → expect atomic actions read + delete.
	ec, err := engine.GetEntityCapabilities(policyRegistry, "test", "public", "organization", map[string]string{"id": "org-1"})
	require.NoError(t, err)
	require.NotNil(t, ec)
	assert.Equal(t, "public", ec.SchemaName)
	assert.Equal(t, "organization", ec.EntityType)
	assert.Equal(t, map[string]string{"id": "org-1"}, ec.EntityKey)
	assert.Contains(t, ec.Actions, "read")
	assert.Contains(t, ec.Actions, "delete")

	// Entity org-99 is not in grants → empty actions, no error.
	ecNoAccess, err := engine.GetEntityCapabilities(policyRegistry, "test", "public", "organization", map[string]string{"id": "org-99"})
	require.NoError(t, err)
	assert.Empty(t, ecNoAccess.Actions)

	t.Logf("Entity capabilities verified for principal %s", matchedIDs[0])
}

// TestGetCapabilities_MultiplePrincipalsMatched verifies that principal matching can return
// more than one principal for the same auth material (OR logic precondition).
func TestGetCapabilities_MultiplePrincipalsMatched(t *testing.T) {
	postgres, err := testutil.RunPostgresWithMigration("testdata/init.sql")
	require.NoError(t, err)
	defer postgres.Cleanup()

	db := postgres.DB
	principalManager, err := NewPrincipalManager(db, nil)
	require.NoError(t, err)

	principal1 := &models.Principal{
		ID:   "principal-1",
		Name: "Principal 1",
		Type: "oidc",
		AuthConfig: models.AuthConfig{
			"claims": []interface{}{
				map[string]interface{}{
					"claim":    "sub",
					"operator": "equals",
					"value":    "shared-user",
				},
			},
		},
		Active: true,
	}
	principal2 := &models.Principal{
		ID:   "principal-2",
		Name: "Principal 2",
		Type: "oidc",
		AuthConfig: models.AuthConfig{
			"claims": []interface{}{
				map[string]interface{}{
					"claim":    "sub",
					"operator": "equals",
					"value":    "shared-user",
				},
			},
		},
		Active: true,
	}
	require.NoError(t, principalManager.CreatePrincipal(principal1))
	require.NoError(t, principalManager.CreatePrincipal(principal2))

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "shared-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	matchedIDs, err := principalManager.MatchPrincipals(context.Background(), tokenString, "oidc")
	require.NoError(t, err)
	assert.Len(t, matchedIDs, 2)
	assert.Contains(t, matchedIDs, "principal-1")
	assert.Contains(t, matchedIDs, "principal-2")

	t.Log("Successfully matched JWT to multiple principals – OR logic precondition verified")
}
