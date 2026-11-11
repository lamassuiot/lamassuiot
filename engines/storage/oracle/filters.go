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
		switch filter.FilterOperation {
		case resources.StringEqual, resources.EnumEqual:
			db = db.Where("? = ?", col, value)
		case resources.StringNotEqual, resources.EnumNotEqual:
			db = db.Where("? <> ?", col, value)
		case resources.StringEqualIgnoreCase, resources.StringNotEqualIgnoreCase, resources.StringContains, resources.StringContainsIgnoreCase, resources.StringNotContains, resources.StringNotContainsIgnoreCase:
			pattern := escapeLike(value)
			op, lhs := "LIKE", "?"
			switch filter.FilterOperation {
			case resources.StringContains, resources.StringContainsIgnoreCase, resources.StringNotContains, resources.StringNotContainsIgnoreCase:
				pattern = "%" + pattern + "%"
			}
			switch filter.FilterOperation {
			case resources.StringNotEqualIgnoreCase, resources.StringNotContains, resources.StringNotContainsIgnoreCase:
				op = "NOT LIKE"
			}
			switch filter.FilterOperation {
			case resources.StringEqualIgnoreCase, resources.StringNotEqualIgnoreCase, resources.StringContainsIgnoreCase, resources.StringNotContainsIgnoreCase:
				lhs = "LOWER(?)"
				pattern = strings.ToLower(pattern)
			}
			db = db.Where(lhs+" "+op+` ? ESCAPE '\'`, col, pattern)
		case resources.StringIn, resources.StringInIgnoreCase, resources.StringNotIn, resources.StringNotInIgnoreCase, resources.EnumIn:
			var values []string
			for _, item := range strings.Split(value, ",") {
				if item != "" {
					values = append(values, item)
				}
			}
			if len(values) == 0 {
				continue
			}
			lhs, op := "?", "IN"
			if filter.FilterOperation == resources.StringInIgnoreCase || filter.FilterOperation == resources.StringNotInIgnoreCase {
				lhs = "LOWER(?)"
				for i := range values {
					values[i] = strings.ToLower(values[i])
				}
			}
			if filter.FilterOperation == resources.StringNotIn || filter.FilterOperation == resources.StringNotInIgnoreCase {
				op = "NOT IN"
			}
			db = db.Where(lhs+" "+op+" ?", col, values)
		case resources.NumberEqual, resources.NumberNotEqual, resources.NumberLessThan, resources.NumberLessOrEqualThan, resources.NumberGreaterThan, resources.NumberGreaterOrEqualThan:
			// The KMS numeric fields are integers. Do not round a 64-bit integer
			// through float64; decimal filters require a separate exact binding.
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid integer filter value %q", value)
			}
			operators := map[resources.FilterOperation]string{resources.NumberEqual: "=", resources.NumberNotEqual: "<>", resources.NumberLessThan: "<", resources.NumberLessOrEqualThan: "<=", resources.NumberGreaterThan: ">", resources.NumberGreaterOrEqualThan: ">="}
			db = db.Where("? "+operators[filter.FilterOperation]+" ?", col, n)
		case resources.DateEqual, resources.DateBefore, resources.DateAfter:
			date, err := time.Parse(time.RFC3339Nano, value)
			if err != nil {
				return nil, fmt.Errorf("invalid date filter value %q: %w", value, err)
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
