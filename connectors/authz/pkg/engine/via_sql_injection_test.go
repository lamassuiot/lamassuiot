package engine_test

import (
	"strings"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	authz "github.com/lamassuiot/lamassuiot/v4/connectors/authz"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/engine"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/models"
)

// Regression tests for the `via` SQL injection (findings/AUTHZ.md:6): a policy's `via` must name a
// relation the schemas declare. One that doesn't is skipped (it grants nothing and never reaches
// the SQL) instead of failing the whole authorization graph.

// filterFor returns the list filter SQL for a single-rule policy; building must never fail.
func filterFor(t *testing.T, schemas *engine.SchemaRegistry, rule *models.Rule, schema, entity string) string {
	t.Helper()
	policies := engine.NewPolicyRegistry()
	if err := policies.AddPolicy(&models.Policy{ID: "p", Name: "p", Rules: []*models.Rule{rule}}); err != nil {
		t.Fatal(err)
	}
	fg, err := engine.NewFilterGenerator(schemas, policies)
	if err != nil {
		t.Fatalf("an undeclared via must not fail the whole graph: %v", err)
	}
	res, err := fg.GenerateListFilter("read", schema, entity)
	if err != nil {
		t.Fatal(err)
	}
	return res.FullSQL
}

// profileRule: a principal may read ONE issuance profile and, through it, the CAs using it
// (ca_certificates.profile_id -> issuance_profiles, the FK lives on the listed ca_certificates).
func profileRule(via string) *models.Rule {
	return &models.Rule{
		Namespace: "pki", SchemaName: "ca", EntityType: "issuance_profile",
		Actions: []string{"read"}, DirectGrants: []string{"profile-1"},
		Relations: []models.RelationRule{{ToSchemaName: "ca", ToEntityType: "ca_certificate", Via: via, Actions: []string{"read"}}},
	}
}

func TestViaScopesCAListingToDeclaredRelation(t *testing.T) {
	schemas, err := authz.PKISchemas()
	if err != nil {
		t.Fatal(err)
	}

	// Runs the engine's SQL on SQLite. Stripping the "ca." Postgres schema prefix is the only
	// non-authentic step; table and column names are the ones in pki.json.
	run := func(sql string) []string {
		db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
		if err != nil {
			t.Fatal(err)
		}
		for _, stmt := range []string{
			`CREATE TABLE ca_certificates (id TEXT PRIMARY KEY, profile_id TEXT)`,
			`CREATE TABLE issuance_profiles (id TEXT PRIMARY KEY)`,
			`INSERT INTO issuance_profiles VALUES ('profile-1')`,
			`INSERT INTO issuance_profiles VALUES ('profile-2')`,
			`INSERT INTO ca_certificates VALUES ('my-ca', 'profile-1')`,            // uses MY profile
			`INSERT INTO ca_certificates VALUES ('other-tenants-ca', 'profile-2')`, // must stay invisible
		} {
			if err := db.Exec(stmt).Error; err != nil {
				t.Fatalf("seed error: %v (%s)", err, stmt)
			}
		}
		var ids []string
		// The engine's SQL is "SELECT *"; wrap it so Scan only reads one column.
		if err := db.Raw("SELECT id FROM (" + strings.ReplaceAll(sql, "ca.", "") + ")").Scan(&ids).Error; err != nil {
			t.Fatalf("query error: %v\nSQL: %s", err, sql)
		}
		return ids
	}

	t.Run("declared via: scoped to the CAs using my profile", func(t *testing.T) {
		ids := run(filterFor(t, schemas, profileRule("profile_id"), "ca", "ca_certificate"))
		if len(ids) != 1 || ids[0] != "my-ca" {
			t.Fatalf("expected exactly [my-ca], got %v", ids)
		}
	})

	t.Run("injected via: grants nothing and never reaches the SQL", func(t *testing.T) {
		sql := filterFor(t, schemas, profileRule("profile_id = j0_0.id OR 1=1 OR ca_certificates.id"), "ca", "ca_certificate")
		if strings.Contains(sql, "1=1") {
			t.Fatalf("the injected via reached the SQL: %s", sql)
		}
		if ids := run(sql); len(ids) != 0 {
			t.Fatalf("expected no CA, got %v", ids)
		}
	})
}

func TestUndeclaredViaIsSkippedNotFatal(t *testing.T) {
	pki, err := authz.PKISchemas()
	if err != nil {
		t.Fatal(err)
	}
	iot := engine.NewSchemaRegistry()
	if err := iot.Load("../../examples/iot/schemas.json", "iot"); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, schema, entity, mustNotContain string
		schemas                              *engine.SchemaRegistry
		rule                                 *models.Rule
	}{
		{"real column that is not a relation", "ca", "ca_certificate", "level", pki, profileRule("level")},
		{"FK on the rule's own entity: the JOIN would use a column the listed table lacks", "ca", "issuance_profile", "profile_id", pki, &models.Rule{
			Namespace: "pki", SchemaName: "ca", EntityType: "ca_certificate", Actions: []string{"read"}, DirectGrants: []string{"ca-1"},
			Relations: []models.RelationRule{{ToSchemaName: "ca", ToEntityType: "issuance_profile", Via: "profile_id", Actions: []string{"read"}}},
		}},
		{"via with a trailing space", "public", "building", "organization_id", iot, &models.Rule{
			Namespace: "iot", SchemaName: "public", EntityType: "organization", Actions: []string{"read"}, DirectGrants: []string{"org-1"},
			Relations: []models.RelationRule{{ToSchemaName: "public", ToEntityType: "building", Via: "organization_id ", Actions: []string{"read"}}},
		}},
		{"wildcard entity rule with a relation", "ca", "ca_certificate", "issuer_meta_id", pki, &models.Rule{
			Namespace: "pki", SchemaName: "ca", EntityType: "*", Actions: []string{"read"},
			Relations: []models.RelationRule{{ToSchemaName: "ca", ToEntityType: "certificate", Via: "issuer_meta_id", Actions: []string{"read"}}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sql := filterFor(t, tc.schemas, tc.rule, tc.schema, tc.entity)
			if !strings.Contains(sql, "WHERE 1 = 0") || strings.Contains(sql, tc.mustNotContain) {
				t.Fatalf("expected a filter that grants nothing and never mentions %q, got: %s", tc.mustNotContain, sql)
			}
		})
	}
}

// The dashboard policy builder writes the relation's name in via, while the bundled policies write
// its FK column; both must resolve to the schema's FK, and the name must never reach the SQL.
func TestViaRelationNameResolvesToSchemaForeignKey(t *testing.T) {
	schemas := engine.NewSchemaRegistry()
	if err := schemas.Load("../../examples/iot/schemas.json", "iot"); err != nil {
		t.Fatal(err)
	}
	for _, via := range []string{"My Org", "organization_id"} {
		sql := filterFor(t, schemas, &models.Rule{
			Namespace: "iot", SchemaName: "public", EntityType: "organization", Actions: []string{"read"}, DirectGrants: []string{"org-1"},
			Relations: []models.RelationRule{{ToSchemaName: "public", ToEntityType: "building", Via: via, Actions: []string{"read"}}},
		}, "public", "building")
		if !strings.Contains(sql, "buildings.organization_id") || strings.Contains(sql, "My Org") {
			t.Fatalf("via=%q must resolve to the schema's organization_id column, got: %s", via, sql)
		}
	}
}
