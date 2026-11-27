package store

import (
	"database/sql"
	"reflect"
	"strings"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/oracle/dialect"
	"gorm.io/gorm"
)

func oracleDryRun(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(dialect.Dialector{Conn: &sql.DB{}}, &gorm.Config{DryRun: true, DisableAutomaticPing: true, SkipDefaultTransaction: true})
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestApplyAuthzFilterArrayContainsBindsValueOutsidePath(t *testing.T) {
	for _, tc := range []struct {
		op       resources.FilterOperation
		value    string
		wantPath string
		wantVars []any
	}{
		{resources.StringArrayContains, "a?b", `'$[*]?(@ == $target)' PASSING :1 AS "target"`, []any{"a?b"}},
		{resources.StringArrayContainsIgnoreCase, "A?B", `'$[*]?(@.lower() == $v0)' PASSING :1 AS "v0"`, []any{"a?b"}},
		{resources.StringArrayContains, "", `'$[*]?(@ == "")'`, nil},
	} {
		db, err := applyAuthzFilter(oracleDryRun(t).Table("principals"), resources.FilterOption{Field: "tags", FilterOperation: tc.op, Value: tc.value})
		if err != nil {
			t.Fatal(err)
		}
		var rows []map[string]any
		stmt := db.Find(&rows).Statement
		sql := stmt.SQL.String()
		if !strings.Contains(sql, tc.wantPath) {
			t.Errorf("op %d value %q: SQL %q missing %q", tc.op, tc.value, sql, tc.wantPath)
		}
		if len(stmt.Vars) != len(tc.wantVars) || (len(tc.wantVars) > 0 && !reflect.DeepEqual(stmt.Vars, tc.wantVars)) {
			t.Errorf("op %d value %q: vars %#v, want %#v", tc.op, tc.value, stmt.Vars, tc.wantVars)
		}
	}
}
