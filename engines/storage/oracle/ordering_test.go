package oracle

import (
	"database/sql"
	"regexp"
	"strings"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/engines/storage/oracle/dialect"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/oracle/migrations"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func buildOrderingSQL(t *testing.T, table string, add func(*gorm.Statement), clauses ...string) (string, []any) {
	t.Helper()
	db, err := gorm.Open(dialect.Dialector{Conn: &sql.DB{}}, &gorm.Config{DryRun: true, DisableAutomaticPing: true})
	if err != nil {
		t.Fatal(err)
	}
	stmt := &gorm.Statement{DB: db, Table: table, Clauses: make(map[string]clause.Clause)}
	add(stmt)
	stmt.Build(clauses...)
	return stmt.SQL.String(), stmt.Vars
}

func TestOrderKeysUseBinaryNLSSortOnlyForTextColumns(t *testing.T) {
	keys := orderKeys{
		newOrderKey("certificates", "subject_common_name", true),
		newOrderKey(clause.CurrentTable, "level", false),
		newOrderKey(clause.CurrentTable, "id", false),
	}
	got, vars := buildOrderingSQL(t, "ca_certificates", func(stmt *gorm.Statement) {
		stmt.AddClause(clause.OrderBy{Expression: keys})
	}, "ORDER BY")
	want := `ORDER BY NLSSORT("CERTIFICATES"."SUBJECT_COMMON_NAME", 'NLS_SORT=BINARY') DESC, "CA_CERTIFICATES"."LEVEL", NLSSORT("CA_CERTIFICATES"."ID", 'NLS_SORT=BINARY')`
	if got != want || len(vars) != 0 {
		t.Fatalf("ORDER BY = %q vars=%v; want %q", got, vars, want)
	}
}

func TestKeysetAfterMatchesOrderKeys(t *testing.T) {
	keys := orderKeys{newOrderKey(clause.CurrentTable, "key_id", false), newOrderKey(clause.CurrentTable, "engine_id", false)}
	got, vars := buildOrderingSQL(t, "kms_keys", func(stmt *gorm.Statement) {
		stmt.AddClause(clause.Where{Exprs: []clause.Expression{keysetAfter{keys: keys, values: []any{"k", "e"}}}})
	}, "WHERE")
	want := `WHERE NLSSORT("KMS_KEYS"."KEY_ID", 'NLS_SORT=BINARY') >= UTL_RAW.CONCAT(NLSSORT(:1, 'NLS_SORT=BINARY')) AND ` +
		`((NLSSORT("KMS_KEYS"."KEY_ID", 'NLS_SORT=BINARY') > UTL_RAW.CONCAT(NLSSORT(:2, 'NLS_SORT=BINARY'))) OR ` +
		`(NLSSORT("KMS_KEYS"."KEY_ID", 'NLS_SORT=BINARY') = UTL_RAW.CONCAT(NLSSORT(:3, 'NLS_SORT=BINARY')) AND NLSSORT("KMS_KEYS"."ENGINE_ID", 'NLS_SORT=BINARY') > UTL_RAW.CONCAT(NLSSORT(:4, 'NLS_SORT=BINARY'))))`
	if got != want {
		t.Fatalf("keyset predicate = %q; want %q", got, want)
	}
	if len(vars) != 4 || vars[0] != "k" || vars[1] != "k" || vars[2] != "k" || vars[3] != "e" {
		t.Fatalf("keyset vars = %v", vars)
	}

	single, _ := buildOrderingSQL(t, "devices", func(stmt *gorm.Statement) {
		stmt.AddClause(clause.Where{Exprs: []clause.Expression{keysetAfter{keys: []orderKey{newOrderKey(clause.CurrentTable, "id", false)}, values: []any{"d"}}}})
	}, "WHERE")
	if want := `WHERE ((NLSSORT("DEVICES"."ID", 'NLS_SORT=BINARY') > UTL_RAW.CONCAT(NLSSORT(:1, 'NLS_SORT=BINARY'))))`; single != want {
		t.Fatalf("single-key keyset predicate = %q; want %q", single, want)
	}
}

// Every table paginated by keyset must have an index whose leading
// expressions match the ORDER BY that listRows generates for it.
func TestBinarySortIndexesCoverKeysetColumns(t *testing.T) {
	keysets := map[string][]string{
		"certificates": {"serial_number"}, "ca_certificates": {"id"}, "kms_keys": {"key_id", "engine_id"},
		"issuance_profiles": {"id"}, "va_role": {"ca_ski"}, "dms": {"id"}, "events": {"event_type"},
		"subscriptions": {"id"}, "devices": {"id"}, "device_events": {"id"}, "device_groups": {"id"},
	}
	index := regexp.MustCompile(`^CREATE INDEX \w+ ON (\w+) \((.*)\)$`)
	found := map[string]string{}
	for _, stmt := range migrations.BinarySortIndexes().Statements {
		match := index.FindStringSubmatch(stmt)
		if match == nil {
			t.Fatalf("unexpected index statement %q", stmt)
		}
		found[match[1]] = match[2]
	}
	for table, columns := range keysets {
		var prefix []string
		for _, column := range columns {
			prefix = append(prefix, "NLSSORT("+column+", 'NLS_SORT=BINARY')")
		}
		want := strings.Join(prefix, ", ") + ", 0"
		if found[table] != want {
			t.Errorf("index on %s = %q; want %q", table, found[table], want)
		}
	}
	if len(found) != len(keysets) {
		t.Errorf("indexed tables %v; want exactly %v", found, keysets)
	}
}

// Wrapping a numeric or temporal column in NLSSORT would sort it as text, and
// leaving a character column unwrapped would make its order depend on the
// session's NLS_SORT. Check every sortable and keyset column against the DDL.
func TestTextSortColumnsMatchMigrations(t *testing.T) {
	column := regexp.MustCompile(`^\s*"?([A-Za-z_][A-Za-z0-9_]*)"?\s+([A-Za-z0-9_]+)`)
	types := map[string]map[string]struct{}{}
	for _, m := range migrations.Plan() {
		for _, stmt := range m.Statements {
			if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(stmt)), "CREATE TABLE") {
				continue
			}
			for _, line := range strings.Split(stmt, "\n")[1:] {
				match := column.FindStringSubmatch(line)
				if match == nil || strings.EqualFold(match[1], "CONSTRAINT") {
					continue
				}
				name := strings.ToLower(match[1])
				if types[name] == nil {
					types[name] = map[string]struct{}{}
				}
				types[name][strings.ToUpper(match[2])] = struct{}{}
			}
		}
	}

	sortable := map[string]struct{}{}
	for _, fields := range []map[string]struct{}{
		certificateSortFields, caSortFields, kmsSortFields, deviceSortFields, deviceEventSortFields, groupSortFields,
		dmsSortFields, eventSortFields, subscriptionSortFields, profileFields, vaFields,
	} {
		for name := range fields {
			sortable[name] = struct{}{}
		}
	}
	// Keyset columns passed to listRows by the repositories.
	for _, name := range []string{"id", "serial_number", "key_id", "engine_id", "event_type", "ca_ski"} {
		sortable[name] = struct{}{}
	}

	for name := range sortable {
		columnTypes := types[name]
		if len(columnTypes) == 0 {
			t.Errorf("sort column %q is not defined by any migration", name)
			continue
		}
		_, isText := columnTypes["VARCHAR2"]
		if isText && len(columnTypes) != 1 {
			t.Errorf("sort column %q has mixed types %v across tables", name, columnTypes)
			continue
		}
		if isText != isTextSortColumn(name) {
			t.Errorf("sort column %q: VARCHAR2=%v but textSortColumns=%v", name, isText, isTextSortColumn(name))
		}
	}
	for name := range textSortColumns {
		if _, ok := sortable[name]; !ok {
			t.Errorf("textSortColumns lists %q, which no repository sorts by", name)
		}
	}
}
