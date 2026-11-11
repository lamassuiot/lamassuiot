package store

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage/pagination"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	oraclestorage "github.com/lamassuiot/lamassuiot/v4/engines/storage/oracle"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var authzColumnPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var authzLikeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// listAuthzRows provides the paging and scalar filters used by Authz stores
// without depending on the PostgreSQL storage engine's query dialect.
func listAuthzRows[T any](ctx context.Context, db *gorm.DB, model *T, primaryKey string, params *resources.QueryParameters, scope func(*gorm.DB) *gorm.DB, exhaustive bool, apply func(T)) (string, error) {
	page, err := pagination.New(params)
	if err != nil {
		return "", err
	}
	primary, err := authzSafeColumn(primaryKey)
	if err != nil {
		return "", err
	}
	var sortColumn clause.Column
	if page.Sort.SortField != "" {
		if page.Sort.JsonPathExpr != "" {
			return "", fmt.Errorf("Authz database JSONPath sorting is not supported")
		}
		sortColumn, err = authzSafeColumn(page.Sort.SortField)
		if err != nil {
			return "", err
		}
		if page.Sort.SortMode != resources.SortModeAsc && page.Sort.SortMode != resources.SortModeDesc {
			return "", fmt.Errorf("invalid sort mode %q", page.Sort.SortMode)
		}
	}

	base := db.WithContext(ctx).Model(model)
	base = base.Preload(clause.Associations)
	if scope != nil {
		base = scope(base)
	}
	for _, filter := range page.Filters {
		base, err = applyAuthzFilter(base, filter)
		if err != nil {
			return "", err
		}
	}

	order := clause.OrderBy{Columns: []clause.OrderByColumn{{Column: primary}}}
	if page.Sort.SortField != "" {
		order = clause.OrderBy{Columns: []clause.OrderByColumn{
			{Column: sortColumn, Desc: page.Sort.SortMode == resources.SortModeDesc},
			{Column: primary},
		}}
	}
	if exhaustive {
		if base.Statement.Schema == nil {
			if err := base.Statement.Parse(model); err != nil {
				return "", err
			}
		}
		primaryField := base.Statement.Schema.LookUpField(primary.Name)
		if primaryField == nil {
			return "", fmt.Errorf("Authz primary key column %q is not mapped to a model field", primary.Name)
		}
		keysetOrder := clause.OrderBy{Columns: []clause.OrderByColumn{{Column: primary}}}
		offset := page.Offset
		var lastKey any
		for {
			var batch []T
			query := base.Session(&gorm.Session{}).Clauses(keysetOrder).Limit(page.Limit)
			if lastKey == nil {
				query = query.Offset(offset)
			} else {
				query = query.Where(clause.Gt{Column: primary, Value: lastKey})
			}
			result := query.Find(&batch)
			if result.Error != nil {
				return "", result.Error
			}
			if len(batch) == 0 {
				return "", nil
			}
			lastKey, _ = primaryField.ValueOf(ctx, reflect.ValueOf(batch[len(batch)-1]))
			for _, row := range batch {
				apply(row)
			}
			if len(batch) < page.Limit {
				return "", nil
			}
		}
	}

	var rows []T
	if err := base.Clauses(order).Offset(page.Offset).Limit(page.Limit + 1).Find(&rows).Error; err != nil {
		return "", err
	}
	hasMore := len(rows) > page.Limit
	if hasMore {
		rows = rows[:page.Limit]
	}
	for _, row := range rows {
		apply(row)
	}
	if !hasMore || params == nil {
		return "", nil
	}
	return page.Next(), nil
}

func authzSafeColumn(name string) (clause.Column, error) {
	name = strings.ReplaceAll(name, ".", "_")
	if !authzColumnPattern.MatchString(name) {
		return clause.Column{}, fmt.Errorf("invalid Authz database column %q", name)
	}
	return clause.Column{Name: name}, nil
}

func applyAuthzFilter(db *gorm.DB, filter resources.FilterOption) (*gorm.DB, error) {
	column, err := authzSafeColumn(filter.Field)
	if err != nil {
		return db, err
	}
	value := filter.Value
	pattern := func(v string) string { return authzLikeEscaper.Replace(v) }
	switch filter.FilterOperation {
	case resources.StringEqual, resources.EnumEqual:
		return db.Where(clause.Eq{Column: column, Value: value}), nil
	case resources.StringNotEqual, resources.EnumNotEqual:
		return db.Where(clause.Neq{Column: column, Value: value}), nil
	case resources.DateEqual:
		date, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return db, fmt.Errorf("invalid date filter value %q: %w", value, err)
		}
		return db.Where(clause.Eq{Column: column, Value: date}), nil
	case resources.NumberEqual, resources.NumberNotEqual:
		number, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return db, fmt.Errorf("invalid integer filter value %q", value)
		}
		if filter.FilterOperation == resources.NumberNotEqual {
			return db.Where(clause.Neq{Column: column, Value: number}), nil
		}
		return db.Where(clause.Eq{Column: column, Value: number}), nil
	case resources.StringEqualIgnoreCase:
		return db.Where(clause.Expr{SQL: "LOWER(?) = LOWER(?)", Vars: []any{column, value}}), nil
	case resources.StringNotEqualIgnoreCase:
		return db.Where(clause.Expr{SQL: "LOWER(?) <> LOWER(?)", Vars: []any{column, value}}), nil
	case resources.StringContains, resources.StringContainsIgnoreCase:
		lhs, match := "?", pattern(value)
		if filter.FilterOperation == resources.StringContainsIgnoreCase {
			lhs, match = "LOWER(?)", strings.ToLower(match)
		}
		return db.Where(clause.Expr{SQL: lhs + " LIKE ? ESCAPE '\\'", Vars: []any{column, "%" + match + "%"}}), nil
	case resources.StringNotContains, resources.StringNotContainsIgnoreCase:
		lhs, match := "?", pattern(value)
		if filter.FilterOperation == resources.StringNotContainsIgnoreCase {
			lhs, match = "LOWER(?)", strings.ToLower(match)
		}
		return db.Where(clause.Expr{SQL: lhs + " NOT LIKE ? ESCAPE '\\'", Vars: []any{column, "%" + match + "%"}}), nil
	case resources.StringIn, resources.EnumIn, resources.StringInIgnoreCase, resources.StringNotIn, resources.StringNotInIgnoreCase:
		values := make([]string, 0)
		for _, part := range strings.Split(value, ",") {
			if part = strings.TrimSpace(part); part != "" {
				if filter.FilterOperation == resources.StringInIgnoreCase || filter.FilterOperation == resources.StringNotInIgnoreCase {
					part = strings.ToLower(part)
				}
				values = append(values, part)
			}
		}
		if len(values) == 0 {
			return db, nil
		}
		anyValues := make([]any, len(values))
		for i := range values {
			anyValues[i] = values[i]
		}
		negated := filter.FilterOperation == resources.StringNotIn || filter.FilterOperation == resources.StringNotInIgnoreCase
		if filter.FilterOperation == resources.StringInIgnoreCase || filter.FilterOperation == resources.StringNotInIgnoreCase {
			operator := "IN"
			if negated {
				operator = "NOT IN"
			}
			return db.Where(clause.Expr{SQL: "LOWER(?) " + operator + " ?", Vars: []any{column, anyValues}}), nil
		}
		if negated {
			return db.Where(clause.Not(clause.IN{Column: column, Values: anyValues})), nil
		}
		return db.Where(clause.IN{Column: column, Values: anyValues}), nil
	case resources.DateBefore, resources.NumberLessThan:
		return applyAuthzOrderedFilter(db, column, value, filter.FilterOperation, "<")
	case resources.DateAfter, resources.NumberGreaterThan:
		return applyAuthzOrderedFilter(db, column, value, filter.FilterOperation, ">")
	case resources.NumberLessOrEqualThan:
		return applyAuthzOrderedFilter(db, column, value, filter.FilterOperation, "<=")
	case resources.NumberGreaterOrEqualThan:
		return applyAuthzOrderedFilter(db, column, value, filter.FilterOperation, ">=")
	case resources.StringArrayContains, resources.StringArrayContainsIgnoreCase:
		ignoreCase := filter.FilterOperation == resources.StringArrayContainsIgnoreCase
		if value == "" {
			path := `$[*]?(@ == "")`
			if ignoreCase {
				path = `$[*]?(@.lower() == "")`
			}
			return db.Where(clause.Expr{SQL: "JSON_EXISTS(?, '" + path + "' ERROR ON ERROR)", Vars: []any{column}}), nil
		}
		path := `$[*]?(@ == $target)`
		if ignoreCase {
			path = `$[*]?(@.lower() == $target)`
			value = strings.ToLower(value)
		}
		return db.Where(clause.Expr{SQL: "JSON_EXISTS(?, '" + path + "' PASSING ? AS \"target\" ERROR ON ERROR)", Vars: []any{column, value}}), nil
	case resources.JsonPathExpression:
		expression, err := oraclestorage.CompileJSONPathPredicate(value, column)
		if err != nil {
			return db, fmt.Errorf("invalid JSONPath filter for %s: %w", filter.Field, err)
		}
		return db.Where(expression), nil
	case resources.UnspecifiedFilter:
		return db, nil
	default:
		return db, fmt.Errorf("Authz database filter operation %d is not supported", filter.FilterOperation)
	}
}

func applyAuthzOrderedFilter(db *gorm.DB, column clause.Column, value string, operation resources.FilterOperation, operator string) (*gorm.DB, error) {
	var bind any
	if operation == resources.DateBefore || operation == resources.DateAfter || operation == resources.DateEqual {
		date, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return db, fmt.Errorf("invalid date filter value %q: %w", value, err)
		}
		bind = date
	} else {
		number, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return db, fmt.Errorf("invalid integer filter value %q", value)
		}
		bind = number
	}
	return db.Where(clause.Expr{SQL: "? " + operator + " ?", Vars: []any{column, bind}}), nil
}
