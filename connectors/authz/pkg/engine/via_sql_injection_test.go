package engine_test

import (
	"fmt"
	"strings"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	authz "github.com/lamassuiot/lamassuiot/v4/connectors/authz"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/engine"
	"github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/models"
)

// Regression test for the `via` SQL injection (findings/AUTHZ.md:6) and its fix:
// resolveRelationForeignKey in graph.go resolves `via` against the schemas' own declared
// relations instead of trusting the policy's string, so it can never reach the SQL unresolved.
//
// Scenario: a principal may read exactly ONE issuance profile ("profile-1") and, through it, the
// CAs that use it, via the real schema relation ca_certificate.profile_id -> issuance_profile.
// That should scope a CA listing to the CAs using that profile. Before the fix, a crafted `via`
// turned the JOIN into a tautology and returned every CA instead; now the policy is rejected
// before any SQL is built.
//
// Run: cd connectors/authz && go test ./pkg/engine/ -run TestViaRelationRejectsUnresolvedForeignKey -v
func TestViaRelationRejectsUnresolvedForeignKey(t *testing.T) {
	schemas, err := authz.PKISchemas()
	if err != nil {
		t.Fatal(err)
	}

	// buildFilterSQL returns the engine's filter SQL for a certificate-scoped policy whose
	// relation to ca_certificate uses via, or the error the engine rejected it with.
	buildFilterSQL := func(via string) (string, error) {
		policies := engine.NewPolicyRegistry()
		p := &models.Policy{ID: "p", Name: "p", Rules: []*models.Rule{{
			Namespace: "pki", SchemaName: "ca", EntityType: "issuance_profile",
			Actions:      []string{"read"},
			DirectGrants: []string{"profile-1"}, // the ONLY issuance profile this principal may read
			Relations: []models.RelationRule{{
				ToSchemaName: "ca", ToEntityType: "ca_certificate",
				Via: via, Actions: []string{"read"},
			}},
		}}}
		if err := policies.AddPolicy(p); err != nil {
			return "", fmt.Errorf("rejected at policy validation: %w", err)
		}
		fg, err := engine.NewFilterGenerator(schemas, policies)
		if err != nil {
			return "", err
		}
		res, err := fg.GenerateListFilter("read", "ca", "ca_certificate")
		if err != nil {
			return "", err
		}
		return res.FullSQL, nil
	}

	// --- Execute the real engine's SQL against a real (SQLite) database. ---
	// Stripping the "ca." Postgres schema prefix is the only non-authentic step: it's a
	// schema-qualification detail of running against Postgres, not part of the bug. Table
	// and column names are copied verbatim from pki.json (ca_certificates, issuance_profiles,
	// profile_id, id); the FK lives on ca_certificates, as it does in the real schema.
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

		sqliteSQL := strings.ReplaceAll(sql, "ca.", "")
		// The engine's own SQL is "SELECT *"; wrap it so Scan only has to read one column.
		var ids []string
		if err := db.Raw("SELECT id FROM (" + sqliteSQL + ")").Scan(&ids).Error; err != nil {
			t.Fatalf("query error: %v\nSQL: %s", err, sqliteSQL)
		}
		return ids
	}

	t.Run("legitimate via: still scoped to the CAs using my profile", func(t *testing.T) {
		sql, err := buildFilterSQL("profile_id")
		if err != nil {
			t.Fatalf("a legitimate, schema-declared via must not be rejected: %v", err)
		}
		fmt.Printf("\nSQL: %s\n", sql)
		ids := run(sql)
		fmt.Printf("CAs returned: %v\n", ids)
		if len(ids) != 1 || ids[0] != "my-ca" {
			t.Fatalf("expected exactly [my-ca], got %v", ids)
		}
	})

	t.Run("injected via: rejected before any SQL is built", func(t *testing.T) {
		via := "profile_id = j0_0.id OR 1=1 OR ca_certificates.id"
		sql, err := buildFilterSQL(via)
		fmt.Printf("\nvia=%q\n", via)
		if err == nil {
			t.Fatalf("expected the injected via to be rejected, but got SQL: %s", sql)
		}
		fmt.Printf("rejected as expected: %v\n", err)
	})

	t.Run("via naming a real column of an unrelated entity: still rejected", func(t *testing.T) {
		// "level" is a real column of ca_certificates, so it is not a nonsense string, but it is not
		// a declared relation to issuance_profile: it must still be rejected, not accepted for "looking real".
		sql, err := buildFilterSQL("level")
		if err == nil {
			t.Fatalf("expected rejection, but got SQL: %s", sql)
		}
		fmt.Printf("\nvia=\"level\" rejected as expected: %v\n", err)
	})
}

// The dashboard policy builder writes the relation's name in via, while the bundled policies write
// its FK column; both must resolve to the schema's FK, and the name must never reach the SQL.
func TestViaRelationNameResolvesToSchemaForeignKey(t *testing.T) {
	schemas := engine.NewSchemaRegistry()
	if err := schemas.Load("../../examples/iot/schemas.json", "iot"); err != nil {
		t.Fatal(err)
	}
	for _, via := range []string{"My Org", "organization_id"} {
		policies := engine.NewPolicyRegistry()
		if err := policies.AddPolicy(&models.Policy{ID: "p", Name: "p", Rules: []*models.Rule{{
			Namespace: "iot", SchemaName: "public", EntityType: "organization",
			Actions: []string{"read"}, DirectGrants: []string{"org-1"},
			Relations: []models.RelationRule{{ToSchemaName: "public", ToEntityType: "building", Via: via, Actions: []string{"read"}}},
		}}}); err != nil {
			t.Fatal(err)
		}
		fg, err := engine.NewFilterGenerator(schemas, policies)
		if err != nil {
			t.Fatalf("via=%q must be accepted: %v", via, err)
		}
		res, err := fg.GenerateListFilter("read", "public", "building")
		if err != nil {
			t.Fatalf("via=%q: %v", via, err)
		}
		if !strings.Contains(res.FullSQL, "buildings.organization_id") || strings.Contains(res.FullSQL, "My Org") {
			t.Fatalf("via=%q must resolve to the schema's organization_id column, got: %s", via, res.FullSQL)
		}
	}
}
