package oracle

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/oracle/dialect"
	"gorm.io/gorm"
)

// Every character column a repository filters by must be classified, so that
// string filters treat Oracle's NULL as the empty string PostgreSQL stores.
func TestEmptyStringColumnsMatchMigrations(t *testing.T) {
	types := migrationColumnTypes()
	filterable := map[string]struct{}{}
	for _, fields := range []map[string]struct{}{
		certificateFilterFields, caFilterFields, kmsFilterFields, deviceFields, deviceEventFields, groupFields,
		dmsFilterFields, eventFields, subscriptionFields, profileFields, vaFields,
	} {
		for name := range fields {
			filterable[name] = struct{}{}
		}
	}
	for name := range filterable {
		columnTypes := types[name]
		if len(columnTypes) == 0 {
			t.Errorf("filter column %q is not defined by any migration", name)
			continue
		}
		_, varchar := columnTypes["VARCHAR2"]
		_, clob := columnTypes["CLOB"]
		isText := varchar || clob
		if isText && len(columnTypes) != 1 {
			t.Errorf("filter column %q has mixed types %v across tables", name, columnTypes)
			continue
		}
		_, listedCLOB := clobFilterColumns[name]
		if clob != listedCLOB {
			t.Errorf("filter column %q: CLOB=%v but clobFilterColumns=%v", name, clob, listedCLOB)
		}
		if varchar != isTextSortColumn(name) {
			t.Errorf("filter column %q: VARCHAR2=%v but textSortColumns=%v", name, varchar, isTextSortColumn(name))
		}
	}
	for name := range clobFilterColumns {
		if _, ok := filterable[name]; !ok {
			t.Errorf("clobFilterColumns lists %q, which no repository filters by", name)
		}
	}
	for name := range postgresNullTextColumns {
		if _, ok := filterable[name]; !ok {
			t.Errorf("postgresNullTextColumns lists %q, which no repository filters by", name)
		}
	}
}

func TestStringFiltersTreatNullAsEmpty(t *testing.T) {
	for _, tc := range []struct {
		name  string
		field string
		op    resources.FilterOperation
		value string
		want  string
	}{
		{"equal empty", "subject_organization", resources.StringEqual, "", `WHERE "T"."SUBJECT_ORGANIZATION" IS NULL`},
		{"not equal keeps empty", "subject_organization", resources.StringNotEqual, "x", `WHERE ("T"."SUBJECT_ORGANIZATION" <> :1 OR "T"."SUBJECT_ORGANIZATION" IS NULL)`},
		{"not equal ignore case keeps empty", "name", resources.StringNotEqualIgnoreCase, "X", `WHERE (LOWER("T"."NAME") <> :1 OR "T"."NAME" IS NULL)`},
		{"contains empty matches empty", "name", resources.StringContains, "", `WHERE ("T"."NAME" LIKE :1 ESCAPE '\' OR "T"."NAME" IS NULL)`},
		{"contains value excludes empty", "name", resources.StringContains, "x", `WHERE "T"."NAME" LIKE :1 ESCAPE '\'`},
		{"not contains keeps empty", "name", resources.StringNotContainsIgnoreCase, "x", `WHERE (LOWER("T"."NAME") NOT LIKE :1 ESCAPE '\' OR "T"."NAME" IS NULL)`},
		{"not contains empty matches nothing", "name", resources.StringNotContains, "", `WHERE "T"."NAME" NOT LIKE :1 ESCAPE '\'`},
		{"in ignores empty items", "name", resources.StringIn, "x,", `WHERE "T"."NAME" IN (:1)`},
		{"in of only empty items applies no filter", "name", resources.StringIn, ",", ``},
		{"not in keeps empty", "status", resources.StringNotIn, "A,,B", `WHERE ("T"."STATUS" NOT IN (:1,:2) OR "T"."STATUS" IS NULL)`},
		{"CLOB column", "description", resources.StringNotContains, "x", `WHERE ("T"."DESCRIPTION" NOT LIKE :1 ESCAPE '\' OR "T"."DESCRIPTION" IS NULL)`},
		{"CLOB equal uses LIKE", "description", resources.StringEqual, "a%b", `WHERE ("T"."DESCRIPTION" LIKE :1 ESCAPE '\')`},
		{"CLOB not equal keeps empty", "description", resources.StringNotEqual, "x", `WHERE (("T"."DESCRIPTION" NOT LIKE :1 ESCAPE '\') OR "T"."DESCRIPTION" IS NULL)`},
		{"CLOB equal empty", "public_key", resources.StringEqual, "", `WHERE "T"."PUBLIC_KEY" IS NULL`},
		{"CLOB in ignore case", "icon", resources.StringInIgnoreCase, "A,,B", `WHERE (LOWER("T"."ICON") LIKE :1 ESCAPE '\' OR LOWER("T"."ICON") LIKE :2 ESCAPE '\')`},
		{"CLOB not in", "icon", resources.StringNotIn, "a,b", `WHERE (("T"."ICON" NOT LIKE :1 ESCAPE '\' AND "T"."ICON" NOT LIKE :2 ESCAPE '\') OR "T"."ICON" IS NULL)`},
		{"CLOB without empty-as-null", "certificate", resources.StringNotEqual, "x", `WHERE ("T"."CERTIFICATE" NOT LIKE :1 ESCAPE '\')`},
		// PostgreSQL stores NULL for these too, so NULL is not an empty value.
		{"nullstring column", "key_id", resources.StringNotEqual, "x", `WHERE "T"."KEY_ID" <> :1`},
		{"pointer column", "parent_id", resources.StringEqual, "", `WHERE "T"."PARENT_ID" = :1`},
		{"boolean column", "is_ca", resources.StringNotEqual, "true", `WHERE "T"."IS_CA" <> :1`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, err := gorm.Open(dialect.Dialector{Conn: &sql.DB{}}, &gorm.Config{DryRun: true, DisableAutomaticPing: true})
			if err != nil {
				t.Fatal(err)
			}
			allowed := map[string]struct{}{tc.field: {}}
			tx, err := applyFilters(db.Table("t"), []resources.FilterOption{{Field: tc.field, FilterOperation: tc.op, Value: tc.value}}, allowed)
			if err != nil {
				t.Fatal(err)
			}
			stmt := tx.Statement
			stmt.Build("WHERE")
			if got := strings.TrimSpace(stmt.SQL.String()); got != tc.want {
				t.Fatalf("SQL = %q; want %q", got, tc.want)
			}
		})
	}
}
