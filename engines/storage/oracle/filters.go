package oracle

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// applyFilters accepts only fields explicitly exposed by a repository. Values
// are always bound, including those restored from a client bookmark.
func applyFilters(db *gorm.DB, filters []resources.FilterOption, allowed map[string]struct{}) (*gorm.DB, error) {
	return applyFiltersOn(db, filters, allowed, nil)
}

// Oracle stores booleans as NUMBER(1), so textual values from the shared query
// contract must be bound as numeric 1/0 for boolean columns.
var oracleBooleanFilterFields = map[string]struct{}{
	"has_private_key": {}, "is_ca": {}, "sign_as_ca": {}, "honor_key_usage": {},
	"honor_extended_key_usages": {}, "honor_subject": {}, "honor_extensions": {},
	"crypto_enforcement_enabled": {}, "crypto_enforcement_allow_rsa_keys": {},
	"crl_regenerate_on_revoke": {},
}

// Oracle stores an empty string as NULL, while PostgreSQL stores Go's empty
// string as an empty value. String filters on these character columns treat
// NULL as the empty string, so that, for example, "not equal to x" keeps rows
// whose value is empty, as it does on PostgreSQL.
//
// clobFilterColumns are the CLOB columns repositories filter by. They are
// character data but cannot be sorted by, and Oracle rejects =, <> and IN on
// CLOB (ORA-22848), so equality filters on them use an escaped LIKE pattern.
var clobFilterColumns = map[string]struct{}{"certificate": {}, "public_key": {}, "icon": {}, "description": {}}

// postgresNullTextColumns hold NULL on PostgreSQL too when the Go value is
// empty (nullstring serializer, *string or nil pointer fields). Treating NULL
// as empty there would match rows that PostgreSQL does not.
var postgresNullTextColumns = map[string]struct{}{"key_id": {}, "parent_id": {}, "certificate": {}}

func emptyStringStoredAsNull(field string) bool {
	if _, ok := postgresNullTextColumns[field]; ok {
		return false
	}
	if _, ok := clobFilterColumns[field]; ok {
		return true
	}
	return isTextSortColumn(field)
}

func parseOracleBooleanFilter(field, value string) (int64, error) {
	switch strings.ToLower(value) {
	case "true":
		return 1, nil
	case "false":
		return 0, nil
	default:
		return 0, fmt.Errorf("invalid boolean filter value %q for %s", value, field)
	}
}

func applyFiltersOn(db *gorm.DB, filters []resources.FilterOption, allowed map[string]struct{}, tables map[string]string) (*gorm.DB, error) {
	for _, filter := range filters {
		field := strings.ReplaceAll(filter.Field, ".", "_")
		if _, ok := allowed[field]; !ok {
			return nil, fmt.Errorf("invalid filter field %q", filter.Field)
		}
		table := tables[field]
		if table == "" {
			table = clause.CurrentTable
		}
		col := clause.Column{Table: table, Name: field}
		value := filter.Value
		_, isBooleanField := oracleBooleanFilterFields[field]
		nullAsEmpty := !isBooleanField && emptyStringStoredAsNull(field)
		if _, isCLOB := clobFilterColumns[field]; isCLOB {
			if expression, handled := clobEqualityFilter(col, filter.FilterOperation, value, nullAsEmpty); handled {
				if expression != nil {
					db = db.Where(expression)
				}
				continue
			}
		}
		switch filter.FilterOperation {
		case resources.UnspecifiedFilter:
			continue
		case resources.StringEqual, resources.EnumEqual:
			if nullAsEmpty && value == "" {
				db = db.Where("? IS NULL", col)
				continue
			}
			var comparison any = value
			if isBooleanField {
				booleanValue, err := parseOracleBooleanFilter(field, value)
				if err != nil {
					return nil, err
				}
				comparison = booleanValue
			}
			db = db.Where("? = ?", col, comparison)
		case resources.StringNotEqual, resources.EnumNotEqual:
			if nullAsEmpty {
				if value == "" {
					db = db.Where("? IS NOT NULL", col)
				} else {
					db = db.Where("(? <> ? OR ? IS NULL)", col, value, col)
				}
				continue
			}
			var comparison any = value
			if isBooleanField {
				booleanValue, err := parseOracleBooleanFilter(field, value)
				if err != nil {
					return nil, err
				}
				comparison = booleanValue
			}
			db = db.Where("? <> ?", col, comparison)
		case resources.StringEqualIgnoreCase, resources.StringNotEqualIgnoreCase, resources.StringContains, resources.StringContainsIgnoreCase, resources.StringNotContains, resources.StringNotContainsIgnoreCase:
			if isBooleanField {
				switch filter.FilterOperation {
				case resources.StringEqualIgnoreCase, resources.StringNotEqualIgnoreCase:
					booleanValue, err := parseOracleBooleanFilter(field, value)
					if err != nil {
						return nil, err
					}
					op := "="
					if filter.FilterOperation == resources.StringNotEqualIgnoreCase {
						op = "<>"
					}
					db = db.Where("? "+op+" ?", col, booleanValue)
					continue
				default:
					return nil, fmt.Errorf("string containment filter is unsupported for boolean field %s", field)
				}
			}
			if nullAsEmpty && (filter.FilterOperation == resources.StringEqualIgnoreCase || filter.FilterOperation == resources.StringNotEqualIgnoreCase) {
				if value == "" {
					op := "IS NULL"
					if filter.FilterOperation == resources.StringNotEqualIgnoreCase {
						op = "IS NOT NULL"
					}
					db = db.Where("? "+op, col)
				} else if filter.FilterOperation == resources.StringNotEqualIgnoreCase {
					db = db.Where("(LOWER(?) <> ? OR ? IS NULL)", col, strings.ToLower(value), col)
				} else {
					db = db.Where("LOWER(?) = ?", col, strings.ToLower(value))
				}
				continue
			}
			pattern := escapeLike(filter.Value)
			op, lhs := "LIKE", "?"
			contains, negated := false, false
			switch filter.FilterOperation {
			case resources.StringContains, resources.StringContainsIgnoreCase, resources.StringNotContains, resources.StringNotContainsIgnoreCase:
				pattern = "%" + pattern + "%"
				contains = true
			}
			switch filter.FilterOperation {
			case resources.StringNotEqualIgnoreCase, resources.StringNotContains, resources.StringNotContainsIgnoreCase:
				op = "NOT LIKE"
				negated = true
			}
			switch filter.FilterOperation {
			case resources.StringEqualIgnoreCase, resources.StringNotEqualIgnoreCase, resources.StringContainsIgnoreCase, resources.StringNotContainsIgnoreCase:
				lhs = "LOWER(?)"
				pattern = strings.ToLower(pattern)
			}
			condition := lhs + " " + op + ` ? ESCAPE '\'`
			// An empty value contains "" and contains no other value, so it
			// matches "contains ''" and "does not contain x".
			if nullAsEmpty && contains && negated == (value != "") {
				db = db.Where("("+condition+" OR ? IS NULL)", col, pattern, col)
			} else {
				db = db.Where(condition, col, pattern)
			}
		case resources.StringIn, resources.StringInIgnoreCase, resources.StringNotIn, resources.StringNotInIgnoreCase, resources.EnumIn:
			// As on PostgreSQL, empty list items are ignored and an empty list
			// applies no restriction.
			var values []any
			for _, item := range strings.Split(filter.Value, ",") {
				if item == "" {
					continue
				}
				if isBooleanField {
					booleanValue, err := parseOracleBooleanFilter(field, item)
					if err != nil {
						return nil, err
					}
					values = append(values, booleanValue)
				} else {
					values = append(values, item)
				}
			}
			if len(values) == 0 {
				continue
			}
			lhs, op := "?", "IN"
			if !isBooleanField && (filter.FilterOperation == resources.StringInIgnoreCase || filter.FilterOperation == resources.StringNotInIgnoreCase) {
				lhs = "LOWER(?)"
				for i := range values {
					if stringValue, ok := values[i].(string); ok {
						values[i] = strings.ToLower(stringValue)
					}
				}
			}
			if filter.FilterOperation == resources.StringNotIn || filter.FilterOperation == resources.StringNotInIgnoreCase {
				op = "NOT IN"
			}
			// An empty value is never in a list of non-empty values.
			if nullAsEmpty && op == "NOT IN" {
				db = db.Where("("+lhs+" NOT IN ? OR ? IS NULL)", col, values, col)
			} else {
				db = db.Where(lhs+" "+op+" ?", col, values)
			}
		case resources.NumberEqual, resources.NumberNotEqual, resources.NumberLessThan, resources.NumberLessOrEqualThan, resources.NumberGreaterThan, resources.NumberGreaterOrEqualThan:
			// The KMS numeric fields are integers. Do not round a 64-bit integer
			// through float64; decimal filters require a separate exact binding.
			n, err := strconv.ParseInt(filter.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid integer filter value %q", filter.Value)
			}
			operators := map[resources.FilterOperation]string{resources.NumberEqual: "=", resources.NumberNotEqual: "<>", resources.NumberLessThan: "<", resources.NumberLessOrEqualThan: "<=", resources.NumberGreaterThan: ">", resources.NumberGreaterOrEqualThan: ">="}
			db = db.Where("? "+operators[filter.FilterOperation]+" ?", col, n)
		case resources.DateEqual, resources.DateBefore, resources.DateAfter:
			date, err := ParseFilterTime(filter.Value)
			if err != nil {
				return nil, err
			}
			operators := map[resources.FilterOperation]string{resources.DateEqual: "=", resources.DateBefore: "<", resources.DateAfter: ">"}
			db = db.Where("? "+operators[filter.FilterOperation]+" ?", col, date)
		case resources.StringArrayContains:
			db = db.Where(jsonArrayContains{column: col, value: value})
		case resources.StringArrayContainsIgnoreCase:
			db = db.Where(jsonArrayContainsIgnoreCase{column: col, value: strings.ToLower(value)})
		case resources.JsonPathExpression:
			expression, err := compileJSONPredicate(value, col)
			if err != nil {
				return nil, fmt.Errorf("invalid JSONPath filter for %s: %w", field, err)
			}
			db = db.Where(expression)
		default:
			return nil, fmt.Errorf("unsupported oracle filter operation %d", filter.FilterOperation)
		}
	}
	return db, nil
}

// clobEqualityFilter rewrites equality and list filters on a CLOB column as
// escaped LIKE patterns, which match exactly and which Oracle accepts on CLOB.
// It reports false for operations that need no rewriting, such as containment
// (already LIKE). A nil expression with true means no restriction applies.
func clobEqualityFilter(col clause.Column, op resources.FilterOperation, value string, nullAsEmpty bool) (clause.Expression, bool) {
	var values []string
	negated, ignoreCase := false, false
	switch op {
	case resources.StringEqual, resources.EnumEqual:
		values = []string{value}
	case resources.StringNotEqual, resources.EnumNotEqual:
		values, negated = []string{value}, true
	case resources.StringEqualIgnoreCase:
		values, ignoreCase = []string{value}, true
	case resources.StringNotEqualIgnoreCase:
		values, negated, ignoreCase = []string{value}, true, true
	case resources.StringIn, resources.EnumIn, resources.StringInIgnoreCase, resources.StringNotIn, resources.StringNotInIgnoreCase:
		// As on PostgreSQL, empty list items are ignored.
		for _, item := range strings.Split(value, ",") {
			if item != "" {
				values = append(values, item)
			}
		}
		if len(values) == 0 {
			return nil, true
		}
		negated = op == resources.StringNotIn || op == resources.StringNotInIgnoreCase
		ignoreCase = op == resources.StringInIgnoreCase || op == resources.StringNotInIgnoreCase
	default:
		return nil, false
	}
	if nullAsEmpty && len(values) == 1 && values[0] == "" {
		if negated {
			return clause.Expr{SQL: "? IS NOT NULL", Vars: []any{col}}, true
		}
		return clause.Expr{SQL: "? IS NULL", Vars: []any{col}}, true
	}
	lhs, like, join := "?", " LIKE ", " OR "
	if ignoreCase {
		lhs = "LOWER(?)"
	}
	if negated {
		like, join = " NOT LIKE ", " AND "
	}
	var terms []string
	var vars []any
	for _, item := range values {
		pattern := escapeLike(item)
		if ignoreCase {
			pattern = strings.ToLower(pattern)
		}
		terms = append(terms, lhs+like+`? ESCAPE '\'`)
		vars = append(vars, col, pattern)
	}
	sql := "(" + strings.Join(terms, join) + ")"
	// An empty value equals none of the given non-empty values.
	if nullAsEmpty && negated {
		sql = "(" + sql + " OR ? IS NULL)"
		vars = append(vars, col)
	}
	return clause.Expr{SQL: sql, Vars: vars}, true
}

// filterTimeLayouts are the date filter formats accepted by both providers.
// PostgreSQL casts the raw filter string to a timestamp, so besides RFC 3339 it
// accepts a date alone and a date and time without a zone, which it reads in
// the session time zone (UTC for Lamassu). Layouts without a zone are parsed
// as UTC.
var filterTimeLayouts = []string{
	time.RFC3339Nano,
	"2006-01-02 15:04:05.999999999Z07:00",
	"2006-01-02T15:04:05.999999999",
	"2006-01-02 15:04:05.999999999",
	time.DateOnly,
}

// ParseFilterTime parses a date filter value as PostgreSQL would, for the
// date formats listed in filterTimeLayouts.
func ParseFilterTime(value string) (time.Time, error) {
	for _, layout := range filterTimeLayouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid date filter value %q: use RFC 3339, YYYY-MM-DD or YYYY-MM-DD[T ]HH:MM:SS", value)
}

// CompileJSONPathPredicate exposes the Oracle JSONPath translator to other
// Lamassu components that need to evaluate JSON filters outside the storage
// repositories, such as Authz's own policy store.
func CompileJSONPathPredicate(expression string, column clause.Column) (clause.Expression, error) {
	return compileJSONPredicate(expression, column)
}

// JSONStringArrayContains returns a predicate that matches rows whose JSON
// array column contains value. It writes the SQL/JSON path as a literal and
// passes the value as a bind, so it can be used where GORM would read a "?"
// inside the path as a bind placeholder. With ignoreCase, array items are
// compared in lower case.
func JSONStringArrayContains(column clause.Column, value string, ignoreCase bool) clause.Expression {
	if ignoreCase {
		return jsonArrayContainsIgnoreCase{column: column, value: strings.ToLower(value)}
	}
	return jsonArrayContains{column: column, value: value}
}

func escapeLike(value string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(value)
}

type jsonArrayContains struct {
	column clause.Column
	value  string
}

type jsonArrayContainsIgnoreCase struct {
	column clause.Column
	value  string
}

func (e jsonArrayContainsIgnoreCase) Build(builder clause.Builder) {
	builder.WriteString("JSON_EXISTS(")
	builder.WriteQuoted(e.column)
	if e.value == "" {
		builder.WriteString(`, '$[*]?(@ == "")' ERROR ON ERROR)`)
		return
	}
	builder.WriteString(", '$[*]?(@.lower() == $v0)' PASSING ")
	builder.AddVar(builder, e.value)
	builder.WriteString(` AS "v0" ERROR ON ERROR)`)
}

func (e jsonArrayContains) Build(builder clause.Builder) {
	builder.WriteString("JSON_EXISTS(")
	builder.WriteQuoted(e.column)
	if e.value == "" {
		builder.WriteString(`, '$[*]?(@ == "")' ERROR ON ERROR)`)
		return
	}
	builder.WriteString(`, '$[*]?(@ == $target)' PASSING `)
	builder.AddVar(builder, e.value)
	builder.WriteString(` AS "target")`)
}
