package oracle

import (
	"errors"
	"strings"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage/pagination"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// listRows shares deterministic offset and keyset pagination across repositories.
// The input query contains repository-specific restrictions and the read alias.
func listRows[T any](tx *gorm.DB, req storage.StorageListRequest[T], filterFields, sortFields map[string]struct{}, tables, aliases map[string]string, uniqueFields []string, lastKey func(T) []any, filterTransforms ...func([]resources.FilterOption) []resources.FilterOption) (string, error) {
	return listRowsWithOptions(tx, req, filterFields, sortFields, tables, aliases, uniqueFields, lastKey, nil, filterTransforms...)
}

func listRowsWithOptions[T any](tx *gorm.DB, req storage.StorageListRequest[T], filterFields, sortFields map[string]struct{}, tables, aliases map[string]string, uniqueFields []string, lastKey func(T) []any, nullAsEmptyFields map[string]struct{}, filterTransforms ...func([]resources.FilterOption) []resources.FilterOption) (string, error) {
	page, err := pagination.New(req.QueryParams)
	if err != nil {
		return "", err
	}
	if req.ApplyFunc == nil {
		return "", errors.New("list callback is required")
	}
	filters := append([]resources.FilterOption(nil), page.Filters...)
	for i := range filters {
		if name := aliases[filters[i].Field]; name != "" {
			filters[i].Field = name
		}
	}
	if len(filterTransforms) > 0 && filterTransforms[0] != nil {
		filters = filterTransforms[0](filters)
	}
	tx, err = applyFiltersOn(tx, filters, filterFields, tables, nullAsEmptyFields)
	if err != nil {
		return "", err
	}
	var order []clause.OrderByColumn
	var jsonOrder *jsonPathOrder
	if page.Sort.SortField != "" {
		name := strings.ReplaceAll(page.Sort.SortField, ".", "_")
		if mapped := aliases[name]; mapped != "" {
			name = mapped
		}
		if _, ok := sortFields[name]; !ok {
			return "", errors.New("invalid or unsupported sort field")
		}
		if page.Sort.JsonPathExpr != "" {
			if page.Sort.SortMode != resources.SortModeAsc && page.Sort.SortMode != resources.SortModeDesc {
				return "", errors.New("invalid sort mode")
			}
			table := tables[name]
			if table == "" {
				table = clause.CurrentTable
			}
			if _, err := sortJSONPath(page.Sort.JsonPathExpr); err != nil {
				return "", err
			}
			jsonOrder = &jsonPathOrder{column: clause.Column{Table: table, Name: name}, path: page.Sort.JsonPathExpr, desc: page.Sort.SortMode == resources.SortModeDesc}
		} else {
			if page.Sort.SortMode != resources.SortModeAsc && page.Sort.SortMode != resources.SortModeDesc {
				return "", errors.New("invalid sort mode")
			}
			table := tables[name]
			if table == "" {
				table = clause.CurrentTable
			}
			order = append(order, clause.OrderByColumn{Column: clause.Column{Table: table, Name: name}, Desc: page.Sort.SortMode == resources.SortModeDesc})
		}
	}
	unique := make([]clause.OrderByColumn, len(uniqueFields))
	for i, field := range uniqueFields {
		unique[i] = clause.OrderByColumn{Column: clause.Column{Table: clause.CurrentTable, Name: field}}
	}
	if req.ExhaustiveRun {
		var last []any
		for {
			query := tx.Session(&gorm.Session{}).Clauses(clause.OrderBy{Columns: unique}).Limit(page.Limit)
			if last == nil {
				query = query.Offset(page.Offset)
			} else {
				if len(last) != len(uniqueFields) {
					return "", errors.New("invalid keyset cursor")
				}
				// Lexicographic comparison also works on Oracle releases without
				// support for ordering tuple expressions.
				var alternatives []clause.Expression
				for i, field := range uniqueFields {
					var terms []clause.Expression
					for j := 0; j < i; j++ {
						terms = append(terms, clause.Eq{Column: unique[j].Column, Value: last[j]})
					}
					terms = append(terms, clause.Gt{Column: clause.Column{Table: clause.CurrentTable, Name: field}, Value: last[i]})
					alternatives = append(alternatives, clause.And(terms...))
				}
				query = query.Where(clause.Or(alternatives...))
			}
			var rows []T
			if err := query.Find(&rows).Error; err != nil {
				return "", err
			}
			if len(rows) == 0 {
				return "", nil
			}
			last = lastKey(rows[len(rows)-1])
			for _, row := range rows {
				req.ApplyFunc(row)
			}
			if len(rows) < page.Limit {
				return "", nil
			}
		}
	}
	var rows []T
	orderClause := clause.OrderBy{Columns: append(order, unique...)}
	if jsonOrder != nil {
		jsonOrder.unique = unique
		orderClause = clause.OrderBy{Expression: jsonOrder}
	}
	if err := tx.Clauses(orderClause).Offset(page.Offset).Limit(page.Limit + 1).Find(&rows).Error; err != nil {
		return "", err
	}
	hasMore := len(rows) > page.Limit
	if hasMore {
		rows = rows[:page.Limit]
	}
	for _, row := range rows {
		req.ApplyFunc(row)
	}
	if hasMore && req.QueryParams != nil {
		return page.Next(), nil
	}
	return "", nil
}
