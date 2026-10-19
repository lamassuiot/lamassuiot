package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	gormlogger "gorm.io/gorm/logger"
)

type filterTestRow struct {
	ID   string
	Name string
}

func dryRunDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.New(postgres.Config{DSN: "host=localhost user=x dbname=x"}), &gorm.Config{
		DryRun:               true,
		DisableAutomaticPing: true,
	})
	if err != nil {
		t.Fatalf("open dry-run db: %v", err)
	}
	return db
}

func TestFilterOperandToWhereClause_QuotesColumn(t *testing.T) {
	db := dryRunDB(t)
	tx := FilterOperandToWhereClause(resources.FilterOption{
		Field:           "subject.common_name",
		FilterOperation: resources.StringEqualIgnoreCase,
		Value:           "foo",
	}, db.Model(&filterTestRow{}))

	var rows []filterTestRow
	stmt := tx.Find(&rows).Statement
	if tx.Error != nil {
		t.Fatalf("unexpected error: %v", tx.Error)
	}
	want := `"subject_common_name" ILIKE $1`
	if got := stmt.SQL.String(); !strings.Contains(got, want) {
		t.Fatalf("SQL %q does not contain %q", got, want)
	}
}

func TestFilterOperandToWhereClause_RejectsInjection(t *testing.T) {
	payloads := []string{
		"id; DROP TABLE x",
		`a" OR 1=1 --`,
		"id OR 1=1",
		"id)--",
		"",
		"1abc",
		"a b",
	}
	for _, p := range payloads {
		db := dryRunDB(t)
		tx := FilterOperandToWhereClause(resources.FilterOption{
			Field:           p,
			FilterOperation: resources.StringEqual,
			Value:           "v",
		}, db.Model(&filterTestRow{}))
		if tx.Error == nil {
			t.Errorf("expected error for field %q", p)
		}
	}
}

func TestPlainOrderColumn(t *testing.T) {
	if _, err := plainOrderColumn("id; DROP TABLE x", "asc"); err == nil {
		t.Error("expected invalid field error")
	}
	if _, err := plainOrderColumn("id", "asc; DROP"); err == nil {
		t.Error("expected invalid mode error")
	}
	c, err := plainOrderColumn("id", "DESC")
	if err != nil || !c.Desc {
		t.Errorf("unexpected result %+v, %v", c, err)
	}
}

func TestBuildJsonPathOrderExpr(t *testing.T) {
	db := dryRunDB(t)
	expr, err := buildJsonPathOrderExpr("metadata", "$.env.priority", "desc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var rows []filterTestRow
	tx := db.Model(&filterTestRow{}).Clauses(clause.OrderBy{Expression: expr}).Find(&rows)
	if tx.Error != nil {
		t.Fatalf("unexpected error: %v", tx.Error)
	}
	sql := tx.Statement.SQL.String()
	if !strings.Contains(sql, `"metadata" #> $1::text[]`) || !strings.HasSuffix(sql, "DESC NULLS LAST") {
		t.Fatalf("unexpected SQL: %s", sql)
	}
	if strings.Contains(sql, "env") || strings.Contains(sql, "priority") {
		t.Fatalf("path must be bound as a parameter, got: %s", sql)
	}
	if got := tx.Statement.Vars[0]; got != "{env,priority}" {
		t.Fatalf("unexpected path param: %v", got)
	}
}

func TestBuildJsonPathOrderExpr_ArrayIndexes(t *testing.T) {
	db := dryRunDB(t)
	cases := map[string]string{
		"$.tags[0]":    "{tags,0}",
		"$.tags[1]":    "{tags,1}",
		"$.tags[last]": "{tags,-1}",
		"$.a[0].b":     "{a,0,b}",
		"$[0]":         "{0}",
	}
	for path, want := range cases {
		expr, err := buildJsonPathOrderExpr("metadata", path, "asc")
		if err != nil {
			t.Errorf("path %q: unexpected error: %v", path, err)
			continue
		}
		var rows []filterTestRow
		tx := db.Model(&filterTestRow{}).Clauses(clause.OrderBy{Expression: expr}).Find(&rows)
		if tx.Error != nil {
			t.Errorf("path %q: unexpected error: %v", path, tx.Error)
			continue
		}
		if got := tx.Statement.Vars[0]; got != want {
			t.Errorf("path %q: path param = %v, want %v", path, got, want)
		}
	}
}

func TestBuildJsonPathOrderExpr_RejectsInjection(t *testing.T) {
	cases := []struct{ field, path string }{
		{"metadata", "$.a'; DROP TABLE x --"},
		{"metadata", "$.a b"},
		{"metadata", "$.a..b"},
		{"metadata", "$."},
		{"metadata", `$.a"b`},
		{"metadata", "$.tags[*]"},
		{"metadata", "$.tags[x]"},
		{"metadata", "$.tags["},
		{"meta data", "$.a"},
		{"metadata; DROP", "$.a"},
	}
	for _, c := range cases {
		if _, err := buildJsonPathOrderExpr(c.field, c.path, "asc"); err == nil {
			t.Errorf("expected error for field=%q path=%q", c.field, c.path)
		}
	}
}

type sqlCaptureLogger struct {
	gormlogger.Interface
	sqls []string
}

func (l *sqlCaptureLogger) Trace(_ context.Context, _ time.Time, fc func() (string, int64), _ error) {
	sql, _ := fc()
	l.sqls = append(l.sqls, sql)
}

func encodeBookmark(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

func TestSelectAll_RejectsMalformedBookmark(t *testing.T) {
	bookmarks := []string{
		"sortM",          // missing ':' used to panic with index out of range
		"off:0;lim",      // same, on a later part
		"off:0;lim:-1;",  // negative limit used to remove the LIMIT clause
		"off:0;lim:0;",   // zero limit
		"off:-5;lim:10;", // negative offset used to remove the OFFSET clause
		"off:x;lim:10;",
	}
	for _, b := range bookmarks {
		db := dryRunDB(t)
		querier := newPostgresDBQuerier[filterTestRow](db, "filter_test_rows", "id")
		_, err := querier.SelectAll(context.Background(), &resources.QueryParameters{NextBookmark: encodeBookmark(b)}, nil, false, func(filterTestRow) {})
		if err == nil {
			t.Errorf("expected error for bookmark %q", b)
		}
	}
}

func TestSelectAll_BookmarkAppliesSortOnce(t *testing.T) {
	db := dryRunDB(t)
	capture := &sqlCaptureLogger{Interface: gormlogger.Discard}
	db.Logger = capture
	querier := newPostgresDBQuerier[filterTestRow](db, "filter_test_rows", "id")

	bookmark := encodeBookmark("off:10;lim:10;sortM:desc;sortB:created_at;filter:" +
		base64.StdEncoding.EncodeToString([]byte("status")) + "-0-" + base64.StdEncoding.EncodeToString([]byte("ACTIVE")) + ";")
	_, err := querier.SelectAll(context.Background(), &resources.QueryParameters{NextBookmark: bookmark}, nil, false, func(filterTestRow) {})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(capture.sqls) == 0 {
		t.Fatal("no SQL captured")
	}
	sql := capture.sqls[len(capture.sqls)-1]
	if got := strings.Count(sql, `"created_at"`); got != 1 {
		t.Fatalf("expected the sort column exactly once, got %d in: %s", got, sql)
	}
	if !strings.Contains(sql, `ORDER BY "created_at" DESC`) || !strings.Contains(sql, "LIMIT 11 OFFSET 10") {
		t.Fatalf("unexpected SQL: %s", sql)
	}
}

func TestFilterOperandToWhereClause_EscapesValues(t *testing.T) {
	cases := []struct {
		op    resources.FilterOperation
		value string
		want  string
	}{
		{resources.StringContains, `50%_a\b`, `%50\%\_a\\b%`},
		{resources.StringNotContainsIgnoreCase, `%`, `%\%%`},
		{resources.StringEqualIgnoreCase, `a_b%`, `a\_b\%`},
		{resources.StringNotEqualIgnoreCase, `a_b`, `a\_b`},
		{resources.StringArrayContainsIgnoreCase, `x%`, `%"x\%"%`},
		{resources.StringArrayContains, `a","b`, `["a\",\"b"]`},
		{resources.StringEqual, `a%`, `a%`}, // plain equality is not a LIKE pattern
	}
	for _, c := range cases {
		db := dryRunDB(t)
		var rows []filterTestRow
		tx := FilterOperandToWhereClause(resources.FilterOption{
			Field:           "name",
			FilterOperation: c.op,
			Value:           c.value,
		}, db.Model(&filterTestRow{})).Find(&rows)
		if tx.Error != nil {
			t.Fatalf("op %v: unexpected error: %v", c.op, tx.Error)
		}
		if got := tx.Statement.Vars[0]; got != c.want {
			t.Errorf("op %v value %q: bound %q, want %q", c.op, c.value, got, c.want)
		}
	}
}

func TestJsonStringArray(t *testing.T) {
	if got := jsonStringArray(`a"]`); got != `["a\"]"]` {
		t.Fatalf("unexpected JSON: %s", got)
	}
}

func TestSafeColumn(t *testing.T) {
	col, err := safeColumn("subject.common_name")
	if err != nil || col.Name != "subject_common_name" {
		t.Fatalf("unexpected result %+v, %v", col, err)
	}
	for _, name := range []string{"", "1abc", "a b", "id;--", `a"b`} {
		if _, err := safeColumn(name); err == nil {
			t.Errorf("expected error for %q", name)
		}
	}
}

func TestPageState_BookmarkRoundTrip(t *testing.T) {
	first, err := newPageState(&resources.QueryParameters{
		PageSize: 10,
		Sort:     resources.SortOptions{SortField: "metadata", SortMode: resources.SortModeDesc, JsonPathExpr: "$.env.priority"},
		Filters: []resources.FilterOption{
			{Field: "status", FilterOperation: resources.EnumEqual, Value: "ACTIVE"},
			{Field: "id", FilterOperation: resources.StringContains, Value: "a-b;c:d"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	second, err := decodeBookmark(first.nextBookmark())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := first
	want.offset = 10
	if !reflect.DeepEqual(second, want) {
		t.Fatalf("round trip mismatch:\n got  %+v\n want %+v", second, want)
	}

	third, err := decodeBookmark(second.nextBookmark())
	if err != nil || third.offset != 20 || third.sort != first.sort {
		t.Fatalf("third page lost state: %+v, %v", third, err)
	}
}

func TestPageState_DefaultSortMode(t *testing.T) {
	page, err := newPageState(&resources.QueryParameters{Sort: resources.SortOptions{SortField: "id"}})
	if err != nil || page.sort.mode != "asc" || page.limit != resources.DefaultPageSize {
		t.Fatalf("unexpected page %+v, %v", page, err)
	}
}

func selectAllSQL(t *testing.T, querier DBQuerier[filterTestRow], params *resources.QueryParameters) string {
	t.Helper()
	capture := &sqlCaptureLogger{Interface: gormlogger.Discard}
	querier.DB.Logger = capture
	if _, err := querier.SelectAll(context.Background(), params, nil, false, func(filterTestRow) {}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(capture.sqls) == 0 {
		t.Fatal("no SQL captured")
	}
	return capture.sqls[len(capture.sqls)-1]
}

func TestSelectAll_UniqueOrder(t *testing.T) {
	cases := []struct {
		name   string
		unique []string
		params *resources.QueryParameters
		want   string
	}{
		{"no sort", nil, nil, `ORDER BY "filter_test_rows"."id" LIMIT ` + strconv.Itoa(resources.DefaultPageSize+1)},
		{"plain sort", nil,
			&resources.QueryParameters{Sort: resources.SortOptions{SortField: "name", SortMode: resources.SortModeDesc}},
			`ORDER BY "name" DESC,"filter_test_rows"."id" LIMIT ` + strconv.Itoa(resources.DefaultPageSize+1)},
		{"json path sort", nil,
			&resources.QueryParameters{Sort: resources.SortOptions{SortField: "metadata", JsonPathExpr: "$.a"}},
			`END ASC NULLS FIRST, "filter_test_rows"."id" LIMIT ` + strconv.Itoa(resources.DefaultPageSize+1)},
		{"composite unique columns", []string{"key_id", "engine_id"}, nil,
			`ORDER BY "filter_test_rows"."key_id","filter_test_rows"."engine_id" LIMIT ` + strconv.Itoa(resources.DefaultPageSize+1)},
	}
	for _, c := range cases {
		querier := newPostgresDBQuerier[filterTestRow](dryRunDB(t), "filter_test_rows", "id")
		if c.unique != nil {
			querier.uniqueColumns = c.unique
		}
		if sql := selectAllSQL(t, querier, c.params); !strings.HasSuffix(sql, c.want) {
			t.Errorf("%s: SQL %q does not end with %q", c.name, sql, c.want)
		}
	}
}

func TestPageState_MaxPageSize(t *testing.T) {
	page, err := newPageState(&resources.QueryParameters{PageSize: resources.MaxPageSize + 1})
	if err != nil || page.limit != resources.MaxPageSize {
		t.Fatalf("expected limit capped to %d, got %+v, %v", resources.MaxPageSize, page, err)
	}
	// bookmarks issued before the cap existed may carry a larger limit: clamp them
	old, err := decodeBookmark(encodeBookmark("off:0;lim:5000;"))
	if err != nil || old.limit != resources.MaxPageSize {
		t.Fatalf("expected legacy bookmark limit clamped to %d, got %+v, %v", resources.MaxPageSize, old, err)
	}
	if _, err := decodeBookmark(encodeBookmark("off:0;lim:0;")); err == nil {
		t.Fatal("expected error for a bookmark with a non-positive limit")
	}
}

// dryRunQuerier returns a querier whose statements are only logged. The default
// transaction is skipped, as opening it would need a real connection.
func dryRunQuerier(t *testing.T, primaryKeyColumn string) (DBQuerier[filterTestRow], *sqlCaptureLogger) {
	t.Helper()
	querier := newPostgresDBQuerier[filterTestRow](dryRunDB(t), "filter_test_rows", primaryKeyColumn)
	querier.DB = querier.DB.Session(&gorm.Session{SkipDefaultTransaction: true})
	capture := &sqlCaptureLogger{Interface: gormlogger.Discard}
	querier.DB.Logger = capture
	return querier, capture
}

func TestSelectExistsUpdateDelete_QuoteColumn(t *testing.T) {
	querier, capture := dryRunQuerier(t, "id")
	ctx := context.Background()

	col := "serial_number"
	if _, _, err := querier.SelectExists(ctx, "x", &col); err != nil {
		t.Fatalf("SelectExists: unexpected error: %v", err)
	}
	// Dry runs affect no rows, so Update and Delete report not found
	if _, err := querier.Update(ctx, &filterTestRow{ID: "x"}, "x"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("Update: unexpected error: %v", err)
	}
	if err := querier.Delete(ctx, "x"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("Delete: unexpected error: %v", err)
	}

	want := []string{`WHERE "serial_number" = 'x'`, `WHERE "id" = 'x'`, `WHERE "id" = 'x'`}
	if len(capture.sqls) != len(want) {
		t.Fatalf("captured %d statements, want %d: %q", len(capture.sqls), len(want), capture.sqls)
	}
	for i, w := range want {
		if !strings.Contains(capture.sqls[i], w) {
			t.Errorf("SQL %q does not contain %q", capture.sqls[i], w)
		}
	}
}

func TestSelectExistsUpdateDelete_RejectInjection(t *testing.T) {
	ctx := context.Background()
	for _, col := range []string{"id = id OR 1=1 --", "id; DROP TABLE x", `"id"`, "id)"} {
		querier, capture := dryRunQuerier(t, col)

		if _, _, err := querier.SelectExists(ctx, "x", &col); err == nil || err.Error() != "invalid column name" {
			t.Errorf("SelectExists: expected invalid column error for %q, got %v", col, err)
		}
		if _, err := querier.Update(ctx, &filterTestRow{ID: "x"}, "x"); err == nil || err.Error() != "invalid column name" {
			t.Errorf("Update: expected invalid column error for %q, got %v", col, err)
		}
		if err := querier.Delete(ctx, "x"); err == nil || err.Error() != "invalid column name" {
			t.Errorf("Delete: expected invalid column error for %q, got %v", col, err)
		}
		if len(capture.sqls) != 0 {
			t.Errorf("column %q: no SQL should be issued, got %q", col, capture.sqls)
		}
	}
}
