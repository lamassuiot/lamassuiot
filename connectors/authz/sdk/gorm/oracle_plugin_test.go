package gorm

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"
	"testing"

	authzsdk "github.com/lamassuiot/lamassuiot/v4/connectors/authz/sdk"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/oracle/dialect"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func TestOracleAuthzGormPluginReturnsNoPrincipalsWithoutGrants(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := NewOracleAuthzGormPlugin().Initialize(db); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`CREATE TABLE principals (id TEXT PRIMARY KEY, auth_config TEXT)`).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`INSERT INTO principals (id, auth_config) VALUES (?, ?)`, "registered", `{"secret":"identity-material"}`).Error; err != nil {
		t.Fatal(err)
	}

	ctx := context.WithValue(context.Background(), authzsdk.AuthzQueryKey, `SELECT * FROM principals WHERE 1 = 0`)
	var principals []map[string]any
	if err := db.WithContext(ctx).Table("principals").Find(&principals).Error; err != nil {
		t.Fatal(err)
	}
	if len(principals) != 0 {
		t.Fatalf("principal without grants received %d principals: %v", len(principals), principals)
	}
}

func TestAuthorizationParsing(t *testing.T) {
	for _, tc := range []struct{ target, query string }{
		{"devices", `SELECT * FROM devicemanager.devices WHERE devicemanager.devices.id IN ('a', 'b''c')`},
		{"devices", `SELECT * FROM devicemanager.devices WHERE 1 = 0 OR devices.id IN ('a')`},
		{"certificates", `SELECT * FROM ca.certificates_view AS certificates WHERE certificates.serial_number IN ('123')`},
		{"certificates", `SELECT * FROM ca.certificates_view certificates LEFT JOIN devicemanager.devices j0_0 ON certificates.subject_common_name = j0_0.id WHERE j0_0.id IS NOT NULL`},
		{"certificates_view certificates", `SELECT * FROM ca.certificates_view AS certificates WHERE certificates.serial_number IN ('123')`},
	} {
		if _, err := parseAuthorization(tc.query, tc.target); err != nil {
			t.Errorf("reject %q: %v", tc.query, err)
		}
	}
	for _, query := range []string{
		`SELECT * FROM ca.devices WHERE devices.id IN ('a')`,
		`SELECT * FROM devicemanager.devices WHERE devices.id IN ('a') OR 1=1; DROP TABLE devices`,
		`SELECT * FROM devicemanager.devices JOIN dms ON 1=1 WHERE 1=1`,
		`SELECT * FROM devicemanager.devices WHERE outsider.id IN ('a')`,
		`SELECT * FROM devicemanager.devices WHERE devices.id IN ('a') OR`,
		`SELECT * FROM devicemanager.devices WHERE devices.id IN ('unterminated)`,
		`SELECT * FROM devicemanager.devices`,
	} {
		if _, err := parseAuthorization(query, "devices"); err == nil {
			t.Errorf("accepted unsupported authorization %q", query)
		}
	}
}

func TestAuthorizationParserBuildsOracleJoinAndBoundPredicate(t *testing.T) {
	db, err := gorm.Open(dialect.Dialector{Conn: &sql.DB{}}, &gorm.Config{DryRun: true, DisableAutomaticPing: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := NewOracleAuthzGormPlugin().Initialize(db); err != nil {
		t.Fatal(err)
	}
	query := `SELECT * FROM devicemanager.devices LEFT JOIN dmsmanager.dms AS j0_0 ON devicemanager.devices.dms_owner = j0_0.id WHERE j0_0.id = 'sample-dms-01' AND j0_0.status = 'ACTIVE'`
	ctx := context.WithValue(context.Background(), authzsdk.AuthzQueryKey, query)
	var rows []map[string]any
	tx := db.WithContext(ctx).Table("devices").Find(&rows)
	if tx.Error != nil {
		t.Fatal(tx.Error)
	}
	sqlText := strings.ToLower(tx.Statement.SQL.String())
	for _, fragment := range []string{
		`left join "dms" j0_0 on "devices"."dms_owner" = "j0_0"."id"`,
		`"j0_0"."id" = :1`,
		`"j0_0"."status" = :2`,
	} {
		if !strings.Contains(sqlText, fragment) {
			t.Errorf("oracle authorization SQL %q missing %q", tx.Statement.SQL.String(), fragment)
		}
	}
	if len(tx.Statement.Vars) != 2 || tx.Statement.Vars[0] != "sample-dms-01" || tx.Statement.Vars[1] != "ACTIVE" {
		t.Fatalf("authorization values were not bound in order: %v", tx.Statement.Vars)
	}
}

func TestAuthorizationParserBuildsTwoHopNullGrant(t *testing.T) {
	db, err := gorm.Open(dialect.Dialector{Conn: &sql.DB{}}, &gorm.Config{DryRun: true, DisableAutomaticPing: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := NewOracleAuthzGormPlugin().Initialize(db); err != nil {
		t.Fatal(err)
	}
	query := `SELECT * FROM ca.certificates_view AS certificates LEFT JOIN devicemanager.devices AS j0_0 ON ca.certificates_view.subject_common_name = j0_0.id LEFT JOIN dmsmanager.dms AS j0_1 ON j0_0.dms_owner = j0_1.id WHERE j0_1.id IS NOT NULL`
	ctx := context.WithValue(context.Background(), authzsdk.AuthzQueryKey, query)
	var rows []map[string]any
	tx := db.WithContext(ctx).Table("certificates_view certificates").Find(&rows)
	if tx.Error != nil {
		t.Fatal(tx.Error)
	}
	sqlText := strings.ToLower(tx.Statement.SQL.String())
	for _, fragment := range []string{
		`left join "devices" j0_0 on "certificates"."subject_common_name" = "j0_0"."id"`,
		`left join "dms" j0_1 on "j0_0"."dms_owner" = "j0_1"."id"`,
		`"j0_1"."id" is not null`,
	} {
		if !strings.Contains(sqlText, fragment) {
			t.Errorf("two-hop Oracle authorization SQL %q missing %q", tx.Statement.SQL.String(), fragment)
		}
	}
}

func TestAuthorizationParserBuildsCompositeKeyJoin(t *testing.T) {
	db, err := gorm.Open(dialect.Dialector{Conn: &sql.DB{}}, &gorm.Config{DryRun: true, DisableAutomaticPing: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := NewOracleAuthzGormPlugin().Initialize(db); err != nil {
		t.Fatal(err)
	}
	query := `SELECT * FROM ca.certificates LEFT JOIN kms.kms_keys AS j0_0 ON ca.certificates.key_id = j0_0.key_id AND ca.certificates.engine_id = j0_0.engine_id WHERE j0_0.key_id IN ('key-1')`
	ctx := context.WithValue(context.Background(), authzsdk.AuthzQueryKey, query)
	var rows []map[string]any
	tx := db.WithContext(ctx).Table("certificates").Find(&rows)
	if tx.Error != nil {
		t.Fatal(tx.Error)
	}
	sqlText := strings.ToLower(tx.Statement.SQL.String())
	if !strings.Contains(sqlText, `"certificates"."key_id" = "j0_0"."key_id" and "certificates"."engine_id" = "j0_0"."engine_id"`) {
		t.Fatalf("composite-key join missing from SQL: %s", tx.Statement.SQL.String())
	}
	if !reflect.DeepEqual(tx.Statement.Vars, []any{"key-1"}) {
		t.Fatalf("composite-key grant value not bound: %v", tx.Statement.Vars)
	}
}

func TestAuthorizationParserTranslatesTypedColumnPredicates(t *testing.T) {
	query := `SELECT * FROM ca.certificates WHERE ca.certificates.is_ca = true AND ca.certificates.key_meta_bits >= 2048 AND ca.certificates.subject_common_name LIKE 'web%'`
	plan, err := parseAuthorization(query, "certificates")
	if err != nil {
		t.Fatal(err)
	}
	db, err := gorm.Open(dialect.Dialector{Conn: &sql.DB{}}, &gorm.Config{DryRun: true, DisableAutomaticPing: true})
	if err != nil {
		t.Fatal(err)
	}
	stmt := &gorm.Statement{DB: db, Table: "CERTIFICATES", Clauses: make(map[string]clause.Clause)}
	stmt.AddClause(clause.Where{Exprs: []clause.Expression{plan.where}})
	stmt.Build("WHERE")
	if !reflect.DeepEqual(stmt.Vars, []any{int64(1), float64(2048), "web%"}) {
		t.Fatalf("typed authorization values=%#v", stmt.Vars)
	}
}

func TestAuthorizationGuardRejectsPrebuiltSQL(t *testing.T) {
	ctx := context.WithValue(context.Background(), authzsdk.AuthzQueryKey,
		`SELECT * FROM devicemanager.devices WHERE devices.id IN ('allowed')`)
	stmt := &gorm.Statement{Context: ctx, Table: "devices"}
	stmt.SQL.WriteString("SELECT * FROM devices")
	tx := &gorm.DB{Config: &gorm.Config{}, Statement: stmt}
	applyAuthorization(tx)
	if !errors.Is(tx.Error, ErrAuthorizationUnsupported) {
		t.Fatalf("prebuilt SQL authorization error=%v, want %v", tx.Error, ErrAuthorizationUnsupported)
	}
}

func TestAuthorizationGuardAddsPredicateToStructuredQuery(t *testing.T) {
	ctx := context.WithValue(context.Background(), authzsdk.AuthzQueryKey,
		`SELECT * FROM devicemanager.devices WHERE devices.id IN ('allowed')`)
	tx := &gorm.DB{Config: &gorm.Config{}, Statement: &gorm.Statement{Context: ctx, Table: "devices", Clauses: make(map[string]clause.Clause)}}
	applyAuthorization(tx)
	if tx.Error != nil {
		t.Fatalf("structured query rejected: %v", tx.Error)
	}
	if _, ok := tx.Statement.Clauses["WHERE"]; !ok {
		t.Fatal("authorization predicate was not added to structured query")
	}
}

func TestAuthorizationGuardSkipsUnrelatedAssociationPreload(t *testing.T) {
	ctx := context.WithValue(context.Background(), authzsdk.AuthzQueryKey,
		`SELECT * FROM devicemanager.devices WHERE devices.id IN ('allowed')`)
	for _, table := range []string{"kms_keys", "custom_association_table"} {
		tx := &gorm.DB{Config: &gorm.Config{}, Statement: &gorm.Statement{Context: ctx, Table: table, Clauses: make(map[string]clause.Clause)}}
		applyAuthorization(tx)
		if tx.Error != nil {
			t.Fatalf("unrelated association preload %q rejected: %v", table, tx.Error)
		}
		if _, ok := tx.Statement.Clauses["WHERE"]; ok {
			t.Fatalf("parent authorization predicate was applied to unrelated preload %q", table)
		}
	}
}

func TestAuthorizationGuardTreatsEmptyQueryAsNoFilter(t *testing.T) {
	ctx := context.WithValue(context.Background(), authzsdk.AuthzQueryKey, "")
	tx := &gorm.DB{Config: &gorm.Config{}, Statement: &gorm.Statement{Context: ctx, Table: "devices", Clauses: make(map[string]clause.Clause)}}
	applyAuthorization(tx)
	if tx.Error != nil {
		t.Fatalf("empty authorization query rejected: %v", tx.Error)
	}
	if _, ok := tx.Statement.Clauses["WHERE"]; ok {
		t.Fatal("empty authorization query added a predicate")
	}
}
