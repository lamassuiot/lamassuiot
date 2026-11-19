package engine

import (
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/models"
)

// In testdata/schemas.tests.json, building declares the relation {name: "My Org", foreign_key:
// "organization_id"} towards organization. A via may name either, so both spellings are the same
// relation and must produce one edge and one JOIN.

func viaNormalizationSchemas(t *testing.T) *SchemaRegistry {
	t.Helper()
	schemas := NewSchemaRegistry()
	if err := schemas.Load("testdata/schemas.tests.json", "iot"); err != nil {
		t.Fatal(err)
	}
	return schemas
}

func orgRule(grant string, rels ...models.RelationRule) *models.Rule {
	return &models.Rule{
		Namespace: "iot", SchemaName: "public", EntityType: "organization",
		Actions: []string{"read"}, DirectGrants: []string{grant}, Relations: rels,
	}
}

func toBuilding(via string, actions ...string) models.RelationRule {
	return models.RelationRule{ToSchemaName: "public", ToEntityType: "building", Via: via, Actions: actions}
}

func policiesOf(t *testing.T, rules ...*models.Rule) *PolicyRegistry {
	t.Helper()
	policies := NewPolicyRegistry()
	for i, rule := range rules {
		id := string(rune('a' + i))
		if err := policies.AddPolicy(&models.Policy{ID: id, Name: id, Rules: []*models.Rule{rule}}); err != nil {
			t.Fatal(err)
		}
	}
	return policies
}

func TestViaSpellingsOfOneRelationShareAnEdge(t *testing.T) {
	policies := policiesOf(t,
		orgRule("org-1", toBuilding("My Org", "read")),
		orgRule("org-2", toBuilding("organization_id", "read")),
	)
	graph := NewAuthorizationGraph()
	if err := graph.BuildFromPoliciesAndSchemas(policies, viaNormalizationSchemas(t)); err != nil {
		t.Fatal(err)
	}
	if paths := graph.FindPathsBetween("public.organization", "public.building", "read", 5); len(paths) != 1 {
		t.Fatalf("want 1 path for one declared relation, got %d", len(paths))
	}
}

func TestViaSpellingsOfOneRelationInOneRuleYieldOneJoin(t *testing.T) {
	policies := policiesOf(t, orgRule("org-1", toBuilding("My Org", "read"), toBuilding("organization_id", "read")))
	fg, err := NewFilterGenerator(viaNormalizationSchemas(t), policies)
	if err != nil {
		t.Fatal(err)
	}
	result, err := fg.GenerateListFilter("read", "public", "building")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Joins) != 1 {
		t.Fatalf("want 1 JOIN for one declared relation, got %d: %v", len(result.Joins), result.Joins)
	}
}

// Every spelling keeps granting: the relation that carries the action is found even when another
// relation to the same target, without the action, is listed first.
func TestViaSpellingGrantsThroughTheRelationThatHasTheAction(t *testing.T) {
	policies := policiesOf(t, orgRule("org-1", toBuilding("My Org", "delete"), toBuilding("organization_id", "read")))
	fg, err := NewFilterGenerator(viaNormalizationSchemas(t), policies)
	if err != nil {
		t.Fatal(err)
	}
	result, err := fg.GenerateListFilter("read", "public", "building")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Joins) != 1 {
		t.Fatalf("read must cascade through the organization_id relation, got joins %v conditions %v", result.Joins, result.Conditions)
	}
}
