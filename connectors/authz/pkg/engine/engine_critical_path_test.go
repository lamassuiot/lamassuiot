package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lamassuiot/lamassuiot/connectors/authz/v3/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// newIoTEngine builds an Engine backed by the in-memory SQLite fixture and the
// IoT example schema, registered under the "iot" config schema so that policy
// rules with namespace "iot" match.
func newIoTEngine(t *testing.T) *Engine {
	t.Helper()
	db := setupTestDB(t)
	engine, err := NewEngine(
		map[string]*gorm.DB{"iot": db},
		map[string]string{"iot": "../../examples/iot/schemas.json"},
	)
	require.NoError(t, err)
	return engine
}

// TestAuthorize_AtomicDenyShortCircuit exercises the early-return branch in
// authorizeAtomic: when no policy grants any access the generated filter is the
// impossible condition "1 = 0", and the engine must deny WITHOUT touching the
// database (no query, no error).
func TestAuthorize_AtomicDenyShortCircuit(t *testing.T) {
	engine := newIoTEngine(t)
	emptyPolicies := NewPolicyRegistry()

	allowed, err := engine.Authorize(
		context.Background(), emptyPolicies,
		"iot", "public", "read", "device",
		map[string]string{"device_id": "device-1"},
	)
	require.NoError(t, err)
	assert.False(t, allowed, "no policy grants access, must deny via 1 = 0 short-circuit")
}

// TestAuthorize_AtomicAllowViaDirectGrant exercises the full allow path: a
// granted entity key that exists in the database returns true and the engine
// collects the matched policy IDs.
func TestAuthorize_AtomicAllowViaDirectGrant(t *testing.T) {
	engine := newIoTEngine(t)
	policies := NewPolicyRegistry()
	require.NoError(t, policies.AddPolicy(&models.Policy{
		ID:   "grant-device-1",
		Name: "Grant device-1",
		Rules: []*models.Rule{
			{
				Namespace:    "iot",
				SchemaName:   "public",
				EntityType:   "device",
				Actions:      []string{"read"},
				DirectGrants: []string{"device-1"},
			},
		},
	}))

	allowed, err := engine.Authorize(
		context.Background(), policies,
		"iot", "public", "read", "device",
		map[string]string{"device_id": "device-1"},
	)
	require.NoError(t, err)
	assert.True(t, allowed, "device-1 is directly granted and exists in DB")
}

// TestAuthorize_AtomicDeniedByDBNoMatch exercises the database deny path: the
// entity exists but the policy does not grant it, so the WHERE clause matches
// no rows and the engine denies.
func TestAuthorize_AtomicDeniedByDBNoMatch(t *testing.T) {
	engine := newIoTEngine(t)
	policies := NewPolicyRegistry()
	require.NoError(t, policies.AddPolicy(&models.Policy{
		ID:   "grant-device-1-only",
		Name: "Grant device-1 only",
		Rules: []*models.Rule{
			{
				Namespace:    "iot",
				SchemaName:   "public",
				EntityType:   "device",
				Actions:      []string{"read"},
				DirectGrants: []string{"device-1"},
			},
		},
	}))

	allowed, err := engine.Authorize(
		context.Background(), policies,
		"iot", "public", "read", "device",
		map[string]string{"device_id": "device-2"},
	)
	require.NoError(t, err)
	assert.False(t, allowed, "device-2 exists but is not granted")
}

// cascadeSchemaJSON is the IoT example graph (organization -> building ->
// gateway -> device) with a filterable "tier" column added to organization so
// that a column-filter rule on the organization can cascade down to devices.
const cascadeSchemaJSON = `[
  {
    "entity_type": "organization",
    "table_name": "organizations",
    "schema_name": "public",
    "primary_key": "id",
    "relations": [],
    "atomic_actions": ["read", "delete"],
    "global_actions": ["write", "list"],
    "filterable": [{ "column": "tier", "type": "string" }]
  },
  {
    "entity_type": "building",
    "table_name": "buildings",
    "schema_name": "public",
    "primary_key": "id",
    "relations": [{ "name": "My Org", "target_entity": "organization", "foreign_key": "organization_id" }],
    "atomic_actions": ["read", "delete"],
    "global_actions": ["write", "list"]
  },
  {
    "entity_type": "gateway",
    "table_name": "iot_gateways",
    "schema_name": "public",
    "primary_key": "id",
    "relations": [{ "name": "building", "target_entity": "building", "foreign_key": "building_id" }],
    "atomic_actions": ["read", "control", "delete"],
    "global_actions": ["write", "list"]
  },
  {
    "entity_type": "device",
    "table_name": "iot_devices",
    "schema_name": "public",
    "primary_key": "device_id",
    "relations": [{ "name": "gateway", "target_entity": "gateway", "foreign_key": "gateway_id" }],
    "atomic_actions": ["read", "control", "delete"],
    "global_actions": ["write", "list"]
  }
]`

// cascadeColumnFilterPolicyJSON grants read on every device reachable from an
// organization whose tier = 'premium', exercising the cascade-by-column-filter
// SQL builders (buildCascadingAccessByColumnFilter / buildPathFilterByColumnFilter).
const cascadeColumnFilterPolicyJSON = `[
  {
    "id": "premium-org-cascade",
    "name": "Premium Org Cascade",
    "rules": [
      {
        "namespace": "iot",
        "schema_name": "public",
        "entity_type": "organization",
        "actions": ["read"],
        "column_filters": [{ "column": "tier", "operator": "eq", "value": "premium" }],
        "relations": [
          {
            "to": { "schema_name": "public", "entity_type": "building" },
            "via": "organization_id",
            "actions": ["read"],
            "relations": [
              {
                "to": { "schema_name": "public", "entity_type": "gateway" },
                "via": "building_id",
                "actions": ["read"],
                "relations": [
                  {
                    "to": { "schema_name": "public", "entity_type": "device" },
                    "via": "gateway_id",
                    "actions": ["read"]
                  }
                ]
              }
            ]
          }
        ]
      }
    ]
  }
]`

// TestGenerateListFilter_CascadeColumnFilter exercises the cascade-by-column-filter
// SQL builders. A column-filter rule on a parent entity (organization.tier =
// 'premium') must cascade through the JOIN graph to the target entity (device),
// producing LEFT JOINs plus an inlined, escaped column-filter condition.
func TestGenerateListFilter_CascadeColumnFilter(t *testing.T) {
	dir := t.TempDir()
	schemaPath := filepath.Join(dir, "schemas.json")
	policyPath := filepath.Join(dir, "policies.json")
	require.NoError(t, os.WriteFile(schemaPath, []byte(cascadeSchemaJSON), 0o600))
	require.NoError(t, os.WriteFile(policyPath, []byte(cascadeColumnFilterPolicyJSON), 0o600))

	schemas := NewSchemaRegistry()
	require.NoError(t, schemas.Load(schemaPath, "iot"))

	policies := NewPolicyRegistry()
	require.NoError(t, policies.Load(policyPath))

	fg := mustNewFilterGenerator(t, schemas, policies)

	result, err := fg.GenerateListFilter("read", "public", "device")
	require.NoError(t, err)

	whereClause := strings.Join(result.Conditions, " AND ")
	require.NotEqual(t, "1 = 0", whereClause, "premium-org cascade should grant access")

	assert.NotEmpty(t, result.Joins, "cascade access must produce JOINs across the graph path")
	assert.Contains(t, whereClause, "tier = 'premium'", "parent column filter must be inlined and escaped")

	joinedJoins := strings.Join(result.Joins, " ")
	assert.Contains(t, joinedJoins, "LEFT JOIN", "cascade path is expressed via LEFT JOINs")
	assert.Contains(t, joinedJoins, "organizations", "path must join up to the organizations table")
}

// TestGenerateListFilter_CascadeColumnFilter_InjectionEscaped ensures that a
// malicious value supplied in a cascading column filter is escaped (single
// quotes doubled) before being inlined into the generated SQL.
func TestGenerateListFilter_CascadeColumnFilter_InjectionEscaped(t *testing.T) {
	dir := t.TempDir()
	schemaPath := filepath.Join(dir, "schemas.json")
	require.NoError(t, os.WriteFile(schemaPath, []byte(cascadeSchemaJSON), 0o600))

	schemas := NewSchemaRegistry()
	require.NoError(t, schemas.Load(schemaPath, "iot"))

	policies := NewPolicyRegistry()
	require.NoError(t, policies.AddPolicy(&models.Policy{
		ID:   "premium-org-cascade-injection",
		Name: "Premium Org Cascade Injection",
		Rules: []*models.Rule{
			{
				Namespace:     "iot",
				SchemaName:    "public",
				EntityType:    "organization",
				Actions:       []string{"read"},
				ColumnFilters: []models.ColumnFilter{{Column: "tier", Operator: "eq", Value: "x'; DROP TABLE devices;--"}},
				Relations: []models.RelationRule{
					{
						To:           models.QualifiedEntityType("building", "public"),
						ToSchemaName: "public",
						ToEntityType: "building",
						Via:          "organization_id",
						Actions:      []string{"read"},
						Relations: []models.RelationRule{
							{
								To:           models.QualifiedEntityType("gateway", "public"),
								ToSchemaName: "public",
								ToEntityType: "gateway",
								Via:          "building_id",
								Actions:      []string{"read"},
								Relations: []models.RelationRule{
									{
										To:           models.QualifiedEntityType("device", "public"),
										ToSchemaName: "public",
										ToEntityType: "device",
										Via:          "gateway_id",
										Actions:      []string{"read"},
									},
								},
							},
						},
					},
				},
			},
		},
	}))

	fg := mustNewFilterGenerator(t, schemas, policies)

	result, err := fg.GenerateListFilter("read", "public", "device")
	require.NoError(t, err)

	whereClause := strings.Join(result.Conditions, " AND ")
	assert.Contains(t, whereClause, "tier = 'x''; DROP TABLE devices;--'", "injection payload must be single-quote escaped")
	assert.NotContains(t, whereClause, "tier = 'x'; DROP TABLE", "raw unescaped payload must not appear")
}
