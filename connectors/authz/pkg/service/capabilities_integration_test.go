package service

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lamassuiot/lamassuiot/connectors/authz/v3/pkg/engine"
	"github.com/lamassuiot/lamassuiot/connectors/authz/v3/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestGetGlobalCapabilities_EndToEnd_JWT ensures the full flow of matching a JWT to a
// principal and deriving global capabilities works correctly.
func TestGetGlobalCapabilities_EndToEnd_JWT(t *testing.T) {
	ctx := context.Background()

	db := setupDBWithAuthzMigrations(t, "testdata/init.sql")

	// test-schema.json has organization with atomicActions=[read,delete], globalActions=[]
	eng, err := engine.NewEngine(
		map[string]*gorm.DB{"test": db},
		map[string]string{"test": "testdata/test-schema.json"},
	)
	require.NoError(t, err)

	principalManager, err := NewPrincipalManager(db, "", false)
	require.NoError(t, err)

	// Build an in-memory policy registry (no blob store needed for this test).
	policyRegistry := engine.NewPolicyRegistry()
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
	require.NoError(t, principalManager.CreatePrincipal(ctx, principal))

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
	gc, err := eng.GetGlobalCapabilities(context.Background(), policyRegistry)
	require.NoError(t, err)
	assert.Empty(t, gc["public.organization"],
		"test schema defines no globalActions for organization, so result must be empty")

	t.Logf("Matched JWT to principal %s; global capabilities verified empty as expected", matchedIDs[0])
}

// TestGetEntityCapabilities_EndToEnd_JWT ensures the full flow of matching a JWT and then
// querying atomic actions for a specific entity works correctly.
func TestGetEntityCapabilities_EndToEnd_JWT(t *testing.T) {
	ctx := context.Background()

	db := setupDBWithAuthzMigrations(t, "testdata/init.sql")

	eng, err := engine.NewEngine(
		map[string]*gorm.DB{"test": db},
		map[string]string{"test": "testdata/test-schema.json"},
	)
	require.NoError(t, err)

	principalManager, err := NewPrincipalManager(db, "", false)
	require.NoError(t, err)

	// Policy: grants read+delete on org-1.
	policyRegistry := engine.NewPolicyRegistry()
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
	require.NoError(t, principalManager.CreatePrincipal(ctx, principal))

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
	ec, err := eng.GetEntityCapabilities(context.Background(), policyRegistry, "test", "public", "organization", map[string]string{"id": "org-1"})
	require.NoError(t, err)
	require.NotNil(t, ec)
	assert.Equal(t, "public", ec.SchemaName)
	assert.Equal(t, "organization", ec.EntityType)
	assert.Equal(t, map[string]string{"id": "org-1"}, ec.EntityKey)
	assert.Contains(t, ec.Actions, "read")
	assert.Contains(t, ec.Actions, "delete")

	// Entity org-99 is not in grants → empty actions, no error.
	ecNoAccess, err := eng.GetEntityCapabilities(context.Background(), policyRegistry, "test", "public", "organization", map[string]string{"id": "org-99"})
	require.NoError(t, err)
	assert.Empty(t, ecNoAccess.Actions)

	t.Logf("Entity capabilities verified for principal %s", matchedIDs[0])
}

// TestGetCapabilities_MultiplePrincipalsMatched verifies that principal matching can return
// more than one principal for the same auth material (OR logic precondition).
func TestGetCapabilities_MultiplePrincipalsMatched(t *testing.T) {
	ctx := context.Background()

	db := setupDBWithAuthzMigrations(t, "testdata/init.sql")
	principalManager, err := NewPrincipalManager(db, "", false)
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
	require.NoError(t, principalManager.CreatePrincipal(ctx, principal1))
	require.NoError(t, principalManager.CreatePrincipal(ctx, principal2))

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

func TestPrincipalManager_MatchSubjects_StaticAndOIDCDerivedAttributes(t *testing.T) {
	ctx := context.Background()

	db := setupDBWithAuthzMigrations(t, "testdata/init.sql")
	principalManager, err := NewPrincipalManager(db, "", false)
	require.NoError(t, err)

	principal := &models.Principal{
		ID:   "principal-oidc-device",
		Name: "OIDC Device",
		Type: "oidc",
		AuthConfig: models.AuthConfig{
			"claims": []interface{}{
				map[string]interface{}{
					"claim":    "sub",
					"operator": "equals",
					"value":    "device-token",
				},
			},
			"subject_attributes": map[string]interface{}{
				"tenant_id": "tenant-a",
			},
			"subject_attribute_mappings": map[string]interface{}{
				"device_id": "oidc.claim.device_id",
			},
		},
		Active: true,
	}
	require.NoError(t, principalManager.CreatePrincipal(ctx, principal))

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":       "device-token",
		"device_id": "device-123",
		"exp":       time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	subjects, err := principalManager.MatchSubjects(ctx, tokenString, "oidc")
	require.NoError(t, err)
	require.Len(t, subjects, 1)
	assert.Equal(t, "principal-oidc-device", subjects[0].PrincipalID)
	assert.Equal(t, "tenant-a", subjects[0].Attributes["tenant_id"])
	assert.Equal(t, "device-123", subjects[0].Attributes["device_id"])
}

func TestPrincipalManager_MatchSubjects_StaticAndX509DerivedAttributes(t *testing.T) {
	ctx := context.Background()

	db := setupDBWithAuthzMigrations(t, "testdata/init.sql")
	principalManager, err := NewPrincipalManager(db, "", false)
	require.NoError(t, err)

	caCert, leafCert, _ := createTestCAAndLeafCerts(t)
	principal := &models.Principal{
		ID:   "principal-x509-device",
		Name: "X509 Device",
		Type: "x509",
		AuthConfig: models.AuthConfig{
			"match_mode": "cn_and_ca",
			"subject_cn": "sensor-*.example.com",
			"ca_trust": map[string]interface{}{
				"pem":           base64PEMFromCert(caCert),
				"identity_type": "authority_key_id",
				"value":         formatAKIValue(leafCert.AuthorityKeyId),
			},
			"subject_attributes": map[string]interface{}{
				"tenant_id": "tenant-a",
			},
			"subject_attribute_mappings": map[string]interface{}{
				"device_id": "x509.subject.cn",
			},
		},
		Active: true,
	}
	require.NoError(t, principalManager.CreatePrincipal(ctx, principal))

	subjects, err := principalManager.MatchSubjects(ctx, leafCert, "x509")
	require.NoError(t, err)
	require.Len(t, subjects, 1)
	assert.Equal(t, "principal-x509-device", subjects[0].PrincipalID)
	assert.Equal(t, "tenant-a", subjects[0].Attributes["tenant_id"])
	assert.Equal(t, "sensor-001.example.com", subjects[0].Attributes["device_id"])
}
