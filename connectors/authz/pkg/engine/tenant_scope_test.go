package engine

import (
	"context"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTenantEngine(t *testing.T) *Engine {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.Exec(`
		CREATE TABLE ca_certificates (
			id VARCHAR(255) PRIMARY KEY,
			tenant_id VARCHAR(255) NOT NULL,
			level INTEGER NOT NULL
		)
	`).Error)
	require.NoError(t, db.Exec(`
		INSERT INTO ca_certificates (id, tenant_id, level) VALUES
			('ca-a1', 'tenant-a', 0),
			('ca-b1', 'tenant-b', 0)
	`).Error)

	schemas := NewSchemaRegistry()
	err = schemas.LoadJSON([]byte(`[
		{
			"entity_type": "ca_certificate",
			"table_name": "ca_certificates",
			"primary_key": "id",
			"atomic_actions": ["read", "delete"],
			"global_actions": ["create"],
			"relations": [],
			"schema_name": "main",
			"filterable": [
				{"column": "level", "type": "int"}
			]
		}
	]`), "pki")
	require.NoError(t, err)

	return &Engine{
		dbs:         map[string]*gorm.DB{"pki": db},
		schemas:     schemas,
		httpSchemas: NewHTTPSchemaRegistry(),
		logger:      engineNopLogger(),
	}
}

func TestEngineAuthorizeEnforcesTenantScopeOverWildcardPolicy(t *testing.T) {
	eng := setupTenantEngine(t)

	policies := NewPolicyRegistry()
	require.NoError(t, policies.AddPolicy(&models.Policy{
		ID:   "wildcard-read",
		Name: "Wildcard Read",
		Rules: []*models.Rule{
			{
				Namespace:    "pki",
				SchemaName:   "main",
				EntityType:   "ca_certificate",
				Actions:      []string{"read"},
				DirectGrants: []string{"*"},
			},
		},
	}))

	ctxTenantA := context.WithValue(context.Background(), core.LamassuContextKeyTenantID, "tenant-a")

	allowedOwn, err := eng.Authorize(ctxTenantA, policies, "pki", "main", "read", "ca_certificate", map[string]string{"id": "ca-a1"})
	require.NoError(t, err)
	assert.True(t, allowedOwn, "wildcard policy must allow own tenant resource")

	allowedOther, err := eng.Authorize(ctxTenantA, policies, "pki", "main", "read", "ca_certificate", map[string]string{"id": "ca-b1"})
	require.NoError(t, err)
	assert.False(t, allowedOther, "wildcard policy must NEVER cross tenant boundary")
}

func TestEngineGetListFilterEnforcesTenantScope(t *testing.T) {
	eng := setupTenantEngine(t)
	ctxTenantA := context.WithValue(context.Background(), core.LamassuContextKeyTenantID, "tenant-a")

	t.Run("wildcard policy still filters by tenant_id", func(t *testing.T) {
		policies := NewPolicyRegistry()
		require.NoError(t, policies.AddPolicy(&models.Policy{
			ID:   "wildcard-read",
			Name: "Wildcard Read",
			Rules: []*models.Rule{
				{
					Namespace:    "pki",
					SchemaName:   "main",
					EntityType:   "ca_certificate",
					Actions:      []string{"read"},
					DirectGrants: []string{"*"},
				},
			},
		}))

		sql, err := eng.GetListFilter(ctxTenantA, policies, "pki", "main", "ca_certificate")
		require.NoError(t, err)
		assert.Equal(t, "SELECT * FROM main.ca_certificates WHERE ca_certificates.tenant_id = 'tenant-a'", sql)
	})

	t.Run("multiple OR policies are wrapped in parentheses inside tenant AND", func(t *testing.T) {
		policies := NewPolicyRegistry()
		require.NoError(t, policies.AddPolicy(&models.Policy{
			ID:   "or-rules",
			Name: "OR Rules",
			Rules: []*models.Rule{
				{
					Namespace:    "pki",
					SchemaName:   "main",
					EntityType:   "ca_certificate",
					Actions:      []string{"read"},
					DirectGrants: []string{"ca-a1"},
				},
				{
					Namespace:  "pki",
					SchemaName: "main",
					EntityType: "ca_certificate",
					Actions:    []string{"read"},
					ColumnFilters: []models.ColumnFilter{
						{Column: "level", Operator: "eq", Value: float64(0), Type: "int"},
					},
				},
			},
		}))

		sql, err := eng.GetListFilter(ctxTenantA, policies, "pki", "main", "ca_certificate")
		require.NoError(t, err)
		assert.Equal(t, "SELECT * FROM main.ca_certificates WHERE ca_certificates.tenant_id = 'tenant-a' AND (ca_certificates.id IN ('ca-a1') OR ca_certificates.level = 0)", sql)
	})

	t.Run("no matching policy stays deny-all even with tenant_id", func(t *testing.T) {
		policies := NewPolicyRegistry()

		sql, err := eng.GetListFilter(ctxTenantA, policies, "pki", "main", "ca_certificate")
		require.NoError(t, err)
		assert.Equal(t, "SELECT * FROM main.ca_certificates WHERE 1 = 0", sql)
	})
}

func TestEngineCascadeJoinEnforcesTenantEqualityOnBothSides(t *testing.T) {
	schemas := NewSchemaRegistry()
	err := schemas.LoadJSON([]byte(`[
		{
			"entity_type": "ca_certificate",
			"table_name": "ca_certificates",
			"primary_key": "id",
			"atomic_actions": ["read"],
			"global_actions": [],
			"relations": [],
			"schema_name": "main"
		},
		{
			"entity_type": "certificate",
			"table_name": "certificates",
			"primary_key": "serial_number",
			"atomic_actions": ["read"],
			"global_actions": [],
			"relations": [
				{
					"name": "issuer_meta_id",
					"target_entity": "ca_certificate",
					"foreign_key": "issuer_meta_id"
				}
			],
			"schema_name": "main"
		}
	]`), "pki")
	require.NoError(t, err)

	policies := NewPolicyRegistry()
	require.NoError(t, policies.AddPolicy(&models.Policy{
		ID:   "ca-cascade",
		Name: "CA Cascade",
		Rules: []*models.Rule{
			{
				Namespace:    "pki",
				SchemaName:   "main",
				EntityType:   "ca_certificate",
				Actions:      []string{"read"},
				DirectGrants: []string{"ca-shared-id"},
				Relations: []models.RelationRule{
					{
						ToSchemaName: "main",
						ToEntityType: "certificate",
						To:           "main.certificate",
						Via:          "issuer_meta_id",
						Actions:      []string{"read"},
					},
				},
			},
		},
	}))

	eng := &Engine{
		schemas:     schemas,
		httpSchemas: NewHTTPSchemaRegistry(),
		logger:      engineNopLogger(),
	}

	ctxTenantA := core.WithTenantID(context.Background(), "tenant-a")
	sql, err := eng.GetListFilter(ctxTenantA, policies, "pki", "main", "certificate")
	require.NoError(t, err)
	assert.Contains(t, sql, "LEFT JOIN main.ca_certificates AS j0_0 ON certificates.issuer_meta_id = j0_0.id AND certificates.tenant_id = j0_0.tenant_id")
	assert.Contains(t, sql, "WHERE certificates.tenant_id = 'tenant-a' AND (")
}
