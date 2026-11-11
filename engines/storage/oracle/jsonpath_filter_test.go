package oracle

import (
	"database/sql"
	"reflect"
	"strings"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/engines/storage/oracle/dialect"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func TestCompileJSONPredicate(t *testing.T) {
	tests := []struct {
		name, input, wantPath string
		wantValues            []any
	}{
		{"string equality", `$.environment == "production"`, `@."environment".type() == "string"`, []any{"production"}},
		{"string inequality", `$.environment != "production"`, `@."environment".type() == "null"`, []any{"production"}},
		{"boolean and numeric", `$.critical == true && $.rotation_days > 30`, `@."rotation_days".type() == "number"`, []any{"+3.0E+01"}},
		{"numeric less than", `$.rotation_days < 30`, `@."rotation_days".numberOnly() < $v0`, []any{"+3.0E+01"}},
		{"numeric less than or equal", `$.rotation_days <= 30`, `@."rotation_days".type() == "null"`, []any{"+3.0E+01"}},
		{"numeric greater than or equal", `$.rotation_days >= 30`, `@."rotation_days".type() == "object"`, []any{"+3.0E+01"}},
		{"null comparison", `$.optional == null`, `@."optional".type() == "null"`, nil},
		{"empty array uses PostgreSQL JSONB rank exception", `$.value < null`, `@."value".type() == "array" && @."value".size() == 0`, nil},
		{"literal left comparison", `30 < $.rotation_days`, `@."rotation_days".numberOnly() > $v0`, []any{"+3.0E+01"}},
		{"or", `$.environment == "production" || $.environment == "staging"`, `@."environment".stringOnly() == $v1`, []any{"production", "staging"}},
		{"starts with", `$.region starts with "us-"`, `@."region".stringOnly() starts with $v0`, []any{"us-"}},
		{"array index", `$.items[0].enabled == true`, `@."items"[0]."enabled".booleanOnly() == true`, nil},
		{"array last", `$.items[last].enabled == true`, `@."items"[last]."enabled".booleanOnly() == true`, nil},
		{"negative array index", `$.items[-2].enabled == true`, `@."items"[last-1]."enabled".booleanOnly() == true`, nil},
		{"array range", `$.items[0 to 2].enabled == true`, `@."items"[0 to 2]."enabled".booleanOnly() == true`, nil},
		{"quoted key", `$."odd key" == "value"`, `@."odd key".stringOnly() == $v0`, []any{"value"}},
		{"numeric item method", `$."temperature c".number() >= 24`, `@."temperature c".number().type() == "number"`, []any{"+2.4E+01"}},
		{"empty string", `$.name == ""`, `@."name".stringOnly() == ""`, nil},
		{"exists function", `$.active == true || exists($.serial_number)`, `exists@."serial_number"`, nil},
		{"nested array string filter", `exists($.tags[*] ? (@ == "production"))`, `@."tags"[*]?(`, []any{"production"}},
		{"nested array numeric filter", `exists($.ports[*]?(@ > 8000))`, `@."ports"[*]?(`, []any{"+8.0E+03"}},
		{"not exists", `$.active == false && !exists($.deleted_at)`, `!(exists@."deleted_at")`, nil},
		{"in list", `$.status in ("ACTIVE", "PENDING")`, `@."status".stringOnly() == $v1`, []any{"ACTIVE", "PENDING"}},
		{"substring", `$.description has substring "gateway"`, `@."description".stringOnly() has substring $v0`, []any{"gateway"}},
		{"regex", `$.hostname like_regex "^api.*"`, `@."hostname".stringOnly() like_regex $v0`, []any{"^api.*"}},
		{"case insensitive regex", `$.description like_regex "PRODUCTION" flag "i"`, `@."description".stringOnly() ci_like_regex $v0`, []any{"PRODUCTION"}},
		{"quoted regex uses literal substring semantics", `$.description like_regex "a.b" flag "q"`, `@."description".stringOnly() has substring $v0`, []any{"a.b"}},
		{"quoted regex ignores multiline flag", `$.description like_regex "^a" flag "qm"`, `@."description".stringOnly() has substring $v0`, []any{"^a"}},
		{"quoted case insensitive regex escapes metacharacters", `$.description like_regex "a.b" flag "iq"`, `@."description".stringOnly() ci_like_regex $v0`, []any{`a\.b`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr, err := compileJSONPredicate(tt.input, clause.Column{Table: clause.CurrentTable, Name: "metadata"})
			if err != nil {
				t.Fatal(err)
			}
			got := expr.(jsonPredicateExpression)
			if got.sql == "" || (!strings.Contains(got.sql, "JSON_EXISTS") && !strings.Contains(got.sql, "JSON_VALUE")) || !reflect.DeepEqual(got.values, tt.wantValues) {
				t.Fatalf("compiled SQL=%q values=%v for expected condition %q and values=%v", got.sql, got.values, tt.wantPath, tt.wantValues)
			}
		})
	}
}

func TestEmptyStringJSONArrayPredicatesAvoidOracleNullBinding(t *testing.T) {
	db, err := gorm.Open(dialect.Dialector{Conn: &sql.DB{}}, &gorm.Config{DryRun: true, DisableAutomaticPing: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, expr := range []clause.Expression{
		jsonArrayContains{column: clause.Column{Name: "tags"}, value: ""},
		jsonArrayContainsIgnoreCase{column: clause.Column{Name: "tags"}, value: ""},
	} {
		stmt := &gorm.Statement{DB: db, Table: "DEVICES", Clauses: make(map[string]clause.Clause)}
		stmt.AddClause(clause.Where{Exprs: []clause.Expression{expr}})
		stmt.Build("WHERE")
		if !strings.Contains(stmt.SQL.String(), `$[*]?(@ == "")`) || strings.Contains(stmt.SQL.String(), "PASSING") || len(stmt.Vars) != 0 {
			t.Errorf("empty string predicate changed through SQL NULL binding: sql=%q vars=%v", stmt.SQL.String(), stmt.Vars)
		}
	}
}

func TestCompileJSONPredicateRejectsUnsupportedAndKeepsStringsBound(t *testing.T) {
	for _, input := range []string{
		`$.field; DROP TABLE devices`,
		`$.field == "x" OR true`,
		`$.items[?(@.key == "x")]`,
		`$.items[last+1].enabled == true`,
		`$.field == "unterminated`,
		`$.left == $.right`,
		`$.left.number() < $.right`,
		`$.left.number() < $.right.string()`,
		`$.field like_regex "x" flag "m"`,
		`$.field like_regex "x" flag "s"`,
	} {
		if _, err := compileJSONPredicate(input, clause.Column{Name: "metadata"}); err == nil {
			t.Errorf("accepted unsupported JSONPath %q", input)
		}
	}
	expr, err := compileJSONPredicate(`$.name == "x' OR 1=1 --"`, clause.Column{Name: "metadata"})
	if err != nil {
		t.Fatal(err)
	}
	got := expr.(jsonPredicateExpression)
	if strings.Contains(got.sql, "OR 1=1") || !reflect.DeepEqual(got.values, []any{"x' OR 1=1 --"}) {
		t.Fatalf("untrusted text was not kept as a bound value: SQL=%q values=%v", got.sql, got.values)
	}

	pathExpr, err := compileJSONPredicate(`$.left.number() < $.right.number()`, clause.Column{Name: "metadata"})
	if err != nil {
		t.Fatal(err)
	}
	pathPredicate := pathExpr.(jsonPredicateExpression)
	if !strings.Contains(pathPredicate.sql, `JSON_VALUE(`) || !strings.Contains(pathPredicate.sql, ` < JSON_VALUE(`) {
		t.Fatalf("typed path comparison was not preserved: %q", pathPredicate.sql)
	}
}

func TestCompileJSONPredicateAllowsLongBoundStringValues(t *testing.T) {
	input := `$.field == "` + strings.Repeat("x", 1000) + `"`
	expr, err := compileJSONPredicate(input, clause.Column{Name: "metadata"})
	if err != nil {
		t.Fatalf("compile long string predicate: %v", err)
	}
	got := expr.(jsonPredicateExpression)
	if len(got.values) != 1 || got.values[0] != strings.Repeat("x", 1000) {
		t.Fatalf("long string literal was not retained as a bind: %d values", len(got.values))
	}
}

func TestCompileJSONPredicateNegationPreservesUnknownSemantics(t *testing.T) {
	for _, tc := range []struct {
		input  string
		checks []string
		values []any
	}{
		{`!($.field == "x")`, []string{`exists@."field"`, `@."field".stringOnly() != $v0`}, []any{"x"}},
		{`!($.field < 2)`, []string{`exists@."field"`, `@."field".numberOnly() >= $v0`}, []any{"+2.0E+00"}},
		{`!($.field starts with "x")`, []string{`exists@."field"`, `@."field".type() == "string"`, `NOT (`}, []any{"x"}},
		{`!($.field in ("x", "y"))`, []string{`exists@."field"`, ` && `, `!= $v0`}, []any{"x", "y"}},
		{`!( $.a == "x" || $.b == "y" )`, []string{`exists@."a"`, `exists@."b"`, ` && `}, []any{"x", "y"}},
		{`!exists($.field)`, []string{`NOT (JSON_EXISTS`}, nil},
	} {
		t.Run(tc.input, func(t *testing.T) {
			expr, err := compileJSONPredicate(tc.input, clause.Column{Name: "metadata"})
			if err != nil {
				t.Fatal(err)
			}
			got := expr.(jsonPredicateExpression)
			for _, check := range tc.checks {
				check = strings.ReplaceAll(check, `exists@."field"`, `JSON_EXISTS`)
				check = strings.ReplaceAll(check, `exists@."a"`, `JSON_EXISTS`)
				check = strings.ReplaceAll(check, `exists@."b"`, `JSON_EXISTS`)
				check = strings.ReplaceAll(check, `@."field".stringOnly()`, `@.stringOnly()`)
				check = strings.ReplaceAll(check, `@."field".numberOnly()`, `@.numberOnly()`)
				check = strings.ReplaceAll(check, `@."field".type()`, `@.type()`)
				if !strings.Contains(got.sql, check) {
					t.Errorf("compiled predicate %q missing %q", got.sql, check)
				}
			}
			if !reflect.DeepEqual(got.values, tc.values) {
				t.Errorf("compiled binds=%v, want %v", got.values, tc.values)
			}
		})
	}
	if _, err := compileJSONPredicate(`!($.left == $.right)`, clause.Column{Name: "metadata"}); err == nil {
		t.Fatal("accepted negated path-to-path comparison")
	}
}

func TestJSONPredicateBuildsOraclePassingClause(t *testing.T) {
	db, err := gorm.Open(dialect.Dialector{Conn: &sql.DB{}}, &gorm.Config{DryRun: true, DisableAutomaticPing: true})
	if err != nil {
		t.Fatal(err)
	}
	stmt := &gorm.Statement{DB: db, Table: "DEVICES", Clauses: make(map[string]clause.Clause)}
	expr, err := compileJSONPredicate(`$.environment == "production"`, clause.Column{Table: clause.CurrentTable, Name: "metadata"})
	if err != nil {
		t.Fatal(err)
	}
	stmt.AddClause(clause.Where{Exprs: []clause.Expression{expr}})
	stmt.Build("WHERE")
	sqlText := stmt.SQL.String()
	for _, expected := range []string{"JSON_EXISTS", `@.type() == "string"`, `@.stringOnly() == $v0`, "PASSING", `AS "v0"`, "ERROR ON ERROR"} {
		if !strings.Contains(sqlText, expected) {
			t.Errorf("generated SQL %q missing %q", sqlText, expected)
		}
	}
	if !reflect.DeepEqual(stmt.Vars, []any{"production"}) {
		t.Fatalf("PASSING variables=%v", stmt.Vars)
	}
}

func TestJSONPredicateBindsExactOracleNumbers(t *testing.T) {
	db, err := gorm.Open(dialect.Dialector{Conn: &sql.DB{}}, &gorm.Config{DryRun: true, DisableAutomaticPing: true})
	if err != nil {
		t.Fatal(err)
	}
	expr, err := compileJSONPredicate(`$.count == 9007199254740993`, clause.Column{Table: clause.CurrentTable, Name: "metadata"})
	if err != nil {
		t.Fatal(err)
	}
	stmt := &gorm.Statement{DB: db, Table: "KMS_KEYS", Clauses: make(map[string]clause.Clause)}
	stmt.AddClause(clause.Where{Exprs: []clause.Expression{expr}})
	stmt.Build("WHERE")
	if !reflect.DeepEqual(stmt.Vars, []any{"+9.007199254740993E+15"}) {
		t.Fatalf("numeric PASSING bind lost precision: %v", stmt.Vars)
	}
	for _, expected := range []string{"TO_NUMBER(", "FMS9D999999999999999EEEE", "NLS_NUMERIC_CHARACTERS=''.,''"} {
		if !strings.Contains(stmt.SQL.String(), expected) {
			t.Errorf("generated SQL %q missing %q", stmt.SQL.String(), expected)
		}
	}
}

func TestOracleJSONNumberBindingLimits(t *testing.T) {
	tests := []struct {
		input, value, format string
		wantError            bool
	}{
		{"1.2300e-2", "+1.23E-02", "FMS9D99EEEE", false},
		{"0", "0.0E+000", "FMS9D9EEEE", false},
		{"123456789012345678901234567890123456789", "", "", true},
		{"1e126", "", "", true},
		{"1e-131", "", "", true},
		{"1e999999999999999999999", "", "", true},
	}
	for _, tc := range tests {
		value, format, err := oracleJSONNumberBinding(tc.input)
		if (err != nil) != tc.wantError || value != tc.value || format != tc.format {
			t.Errorf("oracleJSONNumberBinding(%q)=(%q,%q,%v), want (%q,%q,error=%v)", tc.input, value, format, err, tc.value, tc.format, tc.wantError)
		}
	}
}
