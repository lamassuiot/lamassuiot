package engine

import (
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/models"
)

// building and site both reach organization through organization_id; department reaches it through
// owner_id, the same column name organization uses for its own ownership edge to user. Edges keyed
// only by via collapse these into one another and silently drop access.
const edgeKeySchemas = `[
  {"entity_type": "organization", "table_name": "organizations", "schema_name": "public", "primary_key": "id",
   "relations": [{"name": "owner", "target_entity": "user", "foreign_key": "owner_id"}],
   "atomic_actions": ["read"], "global_actions": ["list"]},
  {"entity_type": "building", "table_name": "buildings", "schema_name": "public", "primary_key": "id",
   "relations": [{"name": "organization", "target_entity": "organization", "foreign_key": "organization_id"}],
   "atomic_actions": ["read"], "global_actions": ["list"]},
  {"entity_type": "site", "table_name": "sites", "schema_name": "public", "primary_key": "id",
   "relations": [{"name": "organization", "target_entity": "organization", "foreign_key": "organization_id"}],
   "atomic_actions": ["read"], "global_actions": ["list"]},
  {"entity_type": "department", "table_name": "departments", "schema_name": "public", "primary_key": "id",
   "relations": [{"name": "organization", "target_entity": "organization", "foreign_key": "owner_id"}],
   "atomic_actions": ["read"], "global_actions": ["list"]},
  {"entity_type": "user", "table_name": "users", "schema_name": "public", "primary_key": "id",
   "atomic_actions": ["read"], "global_actions": ["list"]}
]`

func TestGraphKeepsRelationsThatShareAVia(t *testing.T) {
	schemas := NewSchemaRegistry()
	if err := schemas.LoadJSON([]byte(edgeKeySchemas), "iot"); err != nil {
		t.Fatal(err)
	}
	rel := func(to, via string) models.RelationRule {
		return models.RelationRule{ToSchemaName: "public", ToEntityType: to, Via: via, Actions: []string{"read"}}
	}
	policies := NewPolicyRegistry()
	if err := policies.AddPolicy(&models.Policy{ID: "p", Name: "p", Rules: []*models.Rule{{
		Namespace: "iot", SchemaName: "public", EntityType: "organization", Actions: []string{"read"},
		Relations: []models.RelationRule{
			rel("building", "organization_id"),
			rel("site", "organization_id"),
			rel("department", "owner_id"),
		},
	}}}); err != nil {
		t.Fatal(err)
	}

	graph := NewAuthorizationGraph()
	if err := graph.BuildFromPoliciesAndSchemas(policies, schemas); err != nil {
		t.Fatal(err)
	}

	for _, target := range []string{"public.building", "public.site", "public.department"} {
		if paths := graph.FindPathsBetween("public.organization", target, "read", 5); len(paths) == 0 {
			t.Errorf("no path from organization to %s: its edge was overwritten by another with the same via", target)
		}
	}
	if paths := graph.FindPathsToUser("public.organization", "read", 5); len(paths) == 0 {
		t.Error("organization lost its ownership edge to user")
	}
}
