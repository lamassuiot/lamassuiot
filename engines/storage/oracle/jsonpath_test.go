package oracle

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/engines/storage/oracle/dialect"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func TestSortJSONPath(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"$.foo.bar", `$."foo"."bar"`},
		{"$.items[last].name", `$."items"[last]."name"`},
		{"$[0].123[12]", `$[0]."123"[12]`},
		{"$.a-b._key", `$."a-b"."_key"`},
	} {
		t.Run(tc.input, func(t *testing.T) {
			got, err := sortJSONPath(tc.input)
			if err != nil || got != tc.want {
				t.Fatalf("sortJSONPath(%q) = %q, %v; want %q", tc.input, got, err, tc.want)
			}
		})
	}
	for _, path := range []string{"$", "$.a' OR 1=1", "$.*", "$.a[0", "$.a[1 to 2]", "$.a?(@.x==1)"} {
		if _, err := sortJSONPath(path); err == nil {
			t.Errorf("sortJSONPath(%q) accepted invalid path", path)
		}
	}
}

func TestJSONPathOrderBuildsOracleExpressionAndStableTieBreaker(t *testing.T) {
	db, err := gorm.Open(dialect.Dialector{Conn: &sql.DB{}}, &gorm.Config{DryRun: true, DisableAutomaticPing: true})
	if err != nil {
		t.Fatal(err)
	}
	stmt := &gorm.Statement{DB: db, Table: "DEVICE", Clauses: make(map[string]clause.Clause)}
	stmt.AddClause(clause.OrderBy{Expression: jsonPathOrder{
		column: clause.Column{Table: clause.CurrentTable, Name: "metadata"},
		path:   "$.env.priority",
		unique: []clause.OrderByColumn{{Column: clause.Column{Table: clause.CurrentTable, Name: "id"}}},
	}})
	stmt.Build("ORDER BY")
	sql := stmt.SQL.String()
	for _, expected := range []string{"lamassu_json_sort_key(CASE WHEN", "JSON_VALUE(\"DEVICE\".\"METADATA\"", "'$.\"env\".\"priority\".numberOnly()'", "RETURNING NUMBER", "LPAD(TO_CHAR", "REGEXP_LIKE(", "TO_TIMESTAMP(", "AS TIMESTAMP(6)", "FF9", "FF6", "JSON_QUERY(\"DEVICE\".\"METADATA\"", "RETURNING CLOB NULL ON EMPTY ERROR ON ERROR", "RETURNING CLOB NULL ON EMPTY NULL ON ERROR", "@.type() == \"array\" || @.type() == \"object\"", "@.stringOnly() == \"\"", "THEN TO_CLOB(CHR(1))", "NULLS FIRST", ", \"DEVICE\".\"ID\""} {
		if !strings.Contains(sql, expected) {
			t.Errorf("ORDER BY SQL %q missing %q", sql, expected)
		}
	}
	if len(stmt.Vars) != 0 {
		t.Errorf("SQL/JSON path must be a validated literal, vars=%v", stmt.Vars)
	}
}
