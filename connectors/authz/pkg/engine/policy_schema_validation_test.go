package engine_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"

	authz "github.com/lamassuiot/lamassuiot/v4/connectors/authz"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/engine"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/models"
)

// A relation `via` the schemas do not declare grants nothing at evaluation time. These tests pin
// that the admin is told about it when the policy is saved and, for policies already stored, in
// the structured log.

func policyWith(rule *models.Rule) *models.Policy {
	return &models.Policy{ID: "p-via", Name: "p-via", Rules: []*models.Rule{rule}}
}

func TestValidatePolicyAgainstSchemasAcceptsDeclaredVia(t *testing.T) {
	schemas, err := authz.PKISchemas()
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.ValidatePolicyAgainstSchemas(policyWith(profileRule("profile_id")), schemas); err != nil {
		t.Fatalf("a via declared by the target schema must be accepted: %v", err)
	}
}

func TestValidatePolicyAgainstSchemasRejectsUndeclaredVia(t *testing.T) {
	schemas, err := authz.PKISchemas()
	if err != nil {
		t.Fatal(err)
	}
	for _, via := range []string{"parent", "profile_id ", "profile_id = j0_0.id OR 1=1"} {
		err := engine.ValidatePolicyAgainstSchemas(policyWith(profileRule(via)), schemas)
		if !errors.Is(err, engine.ErrUndeclaredVia) {
			t.Errorf("via %q: want ErrUndeclaredVia, got %v", via, err)
		}
	}
}

func TestValidatePolicyAgainstSchemasChecksNestedRelations(t *testing.T) {
	schemas, err := authz.PKISchemas()
	if err != nil {
		t.Fatal(err)
	}
	rule := profileRule("profile_id")
	rule.Relations[0].Relations = []models.RelationRule{
		{ToSchemaName: "ca", ToEntityType: "issuance_profile", Via: "parent", Actions: []string{"read"}},
	}
	if err := engine.ValidatePolicyAgainstSchemas(policyWith(rule), schemas); !errors.Is(err, engine.ErrUndeclaredVia) {
		t.Fatalf("a bad via in a nested relation must be rejected, got %v", err)
	}
}

// A wildcard rule is concretized per schema and a via legitimately resolves for some matches and
// not others, so it is accepted when at least one match resolves it.
func TestValidatePolicyAgainstSchemasAcceptsWildcardViaResolvedByOneMatch(t *testing.T) {
	schemas, err := authz.PKISchemas()
	if err != nil {
		t.Fatal(err)
	}
	rule := profileRule("profile_id")
	rule.EntityType = "*"
	if err := engine.ValidatePolicyAgainstSchemas(policyWith(rule), schemas); err != nil {
		t.Fatalf("a wildcard via that resolves for one matched schema must be accepted: %v", err)
	}
}

func TestValidatePolicyAgainstSchemasRejectsWildcardViaNoMatchResolves(t *testing.T) {
	schemas, err := authz.PKISchemas()
	if err != nil {
		t.Fatal(err)
	}
	rule := profileRule("parent")
	rule.EntityType = "*"
	if err := engine.ValidatePolicyAgainstSchemas(policyWith(rule), schemas); !errors.Is(err, engine.ErrUndeclaredVia) {
		t.Fatalf("a wildcard via no matched schema resolves grants nothing and must be rejected, got %v", err)
	}
}

// An unloaded relation target is fatal when the graph is built, so it must be rejected at save
// time whether or not the rule uses a wildcard.
func TestValidatePolicyAgainstSchemasRejectsUnloadedRelationTarget(t *testing.T) {
	schemas, err := authz.PKISchemas()
	if err != nil {
		t.Fatal(err)
	}
	for _, entityType := range []string{"issuance_profile", "*"} {
		rule := profileRule("profile_id")
		rule.EntityType = entityType
		rule.Relations[0].ToEntityType = "no_such_entity"
		err := engine.ValidatePolicyAgainstSchemas(policyWith(rule), schemas)
		if !errors.Is(err, engine.ErrPolicySchemaMismatch) {
			t.Errorf("entityType %q: want ErrPolicySchemaMismatch, got %v", entityType, err)
		}
	}
}

func TestValidatePolicyAgainstSchemasRejectsRelationsFromUnloadedEntity(t *testing.T) {
	schemas, err := authz.PKISchemas()
	if err != nil {
		t.Fatal(err)
	}
	rule := profileRule("profile_id")
	rule.EntityType = "no_such_entity"
	if err := engine.ValidatePolicyAgainstSchemas(policyWith(rule), schemas); !errors.Is(err, engine.ErrPolicySchemaMismatch) {
		t.Fatalf("want ErrPolicySchemaMismatch, got %v", err)
	}
}

// Every schema mismatch shares one sentinel so the API maps all of them to 400.
func TestValidatePolicyAgainstSchemasUndeclaredViaIsSchemaMismatch(t *testing.T) {
	schemas, err := authz.PKISchemas()
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.ValidatePolicyAgainstSchemas(policyWith(profileRule("parent")), schemas); !errors.Is(err, engine.ErrPolicySchemaMismatch) {
		t.Fatalf("want ErrPolicySchemaMismatch, got %v", err)
	}
}

func TestSkippedViaIsLoggedWithPolicyAndVia(t *testing.T) {
	schemas, err := authz.PKISchemas()
	if err != nil {
		t.Fatal(err)
	}
	policies := engine.NewPolicyRegistry()
	if err := policies.AddPolicy(policyWith(profileRule("parent"))); err != nil {
		t.Fatal(err)
	}

	logger, hook := logrustest.NewNullLogger()
	if _, err := engine.NewFilterGenerator(schemas, policies, engine.WithGraphLogger(logrus.NewEntry(logger))); err != nil {
		t.Fatal(err)
	}

	for _, e := range hook.AllEntries() {
		if e.Level == logrus.WarnLevel && e.Data["policy_id"] == "p-via" && e.Data["via"] == "parent" {
			return
		}
	}
	t.Fatalf("expected a warning naming policy_id=p-via and via=parent, got %d entries: %v", len(hook.AllEntries()), messages(hook))
}

func messages(h *logrustest.Hook) []string {
	var out []string
	for _, e := range h.AllEntries() {
		out = append(out, strings.TrimSpace(e.Message))
	}
	return out
}
