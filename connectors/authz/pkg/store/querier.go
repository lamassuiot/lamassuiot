package store

// postgresDBQuerier is a generic, Postgres-backed GORM querier that mirrors the one
// in engines/storage/postgres. It cannot be imported from there because that module
// has a reverse dependency on github.com/lamassuiot/authz/sdk/gorm (circular). The
// implementation is kept in sync manually; the authoritative source is
// engines/storage/postgres/utils.go.

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type postgresDBQuerier[E any] struct {
	*gorm.DB
	tableName        string
	primaryKeyColumn string
}

func newPostgresDBQuerier[E any](db *gorm.DB, tableName string, primaryKeyColumn string) postgresDBQuerier[E] {
	return postgresDBQuerier[E]{
		DB:               db,
		tableName:        tableName,
		primaryKeyColumn: primaryKeyColumn,
	}
}

type gormExtraOps struct {
	query           interface{}
	additionalWhere []interface{}
	joins           []string
}

func applyExtraOpts(tx *gorm.DB, extraOpts []gormExtraOps) *gorm.DB {
	for _, op := range extraOpts {
		for _, j := range op.joins {
			tx = tx.Joins(j)
		}
	}
	for _, op := range extraOpts {
		tx = tx.Where(op.query, op.additionalWhere...)
	}
	return tx
}

func (q *postgresDBQuerier[E]) Count(ctx context.Context, extraOpts []gormExtraOps) (int, error) {
	var count int64
	tx := q.Table(q.tableName).WithContext(ctx)
	tx = applyExtraOpts(tx, extraOpts)
	tx.Count(&count)
	if err := tx.Error; err != nil {
		return -1, err
	}
	return int(count), nil
}

func (q *postgresDBQuerier[E]) CountFiltered(ctx context.Context, filters []resources.FilterOption, extraOpts []gormExtraOps) (int, error) {
	var count int64
	tx := q.Table(q.tableName).WithContext(ctx)
	for _, f := range filters {
		tx = FilterOperandToWhereClause(f, tx)
	}
	tx = applyExtraOpts(tx, extraOpts)
	tx.Count(&count)
	if err := tx.Error; err != nil {
		return -1, err
	}
	return int(count), nil
}

func (q *postgresDBQuerier[E]) SelectAll(ctx context.Context, queryParams *resources.QueryParameters, extraOpts []gormExtraOps, exhaustiveRun bool, applyFunc func(E)) (string, error) {
	var elems []E
	tx := q.Table(q.tableName)

	offset := 0
	limit := 15
	var sortMode, sortBy, jsonPathExpr string
	nextBookmark := ""

	if queryParams != nil {
		if queryParams.NextBookmark == "" {
			if queryParams.PageSize > 0 {
				limit = queryParams.PageSize
			}
			if queryParams.Sort.SortMode == "" {
				sortMode = string(resources.SortModeAsc)
			} else {
				sortMode = string(queryParams.Sort.SortMode)
			}

			nextBookmark = fmt.Sprintf("off:%d;lim:%d;", limit+offset, limit)

			if queryParams.Sort.SortField != "" {
				if queryParams.Sort.JsonPathExpr != "" {
					orderClause := buildJsonPathOrderClause(queryParams.Sort.SortField, queryParams.Sort.JsonPathExpr, "")
					nextBookmark += fmt.Sprintf("sortM:%s;sortJP:%s;sortB:%s;", sortMode,
						base64.StdEncoding.EncodeToString([]byte(queryParams.Sort.JsonPathExpr)),
						queryParams.Sort.SortField)
					if sortMode == "desc" {
						tx = tx.Clauses(clause.OrderBy{Expression: gorm.Expr(orderClause + " DESC NULLS LAST")})
					} else {
						tx = tx.Clauses(clause.OrderBy{Expression: gorm.Expr(orderClause + " ASC NULLS FIRST")})
					}
				} else {
					sortBy = strings.ReplaceAll(queryParams.Sort.SortField, ".", "_")
					nextBookmark += fmt.Sprintf("sortM:%s;sortB:%s;", sortMode, sortBy)
					tx = tx.Order(sortBy + " " + sortMode)
				}
			}

			for _, f := range queryParams.Filters {
				tx = FilterOperandToWhereClause(f, tx)
				nextBookmark += fmt.Sprintf("filter:%s-%d-%s;",
					base64.StdEncoding.EncodeToString([]byte(f.Field)),
					f.FilterOperation,
					base64.StdEncoding.EncodeToString([]byte(f.Value)))
			}
		} else {
			nextBookmark = ""
			decoded, err := base64.RawURLEncoding.DecodeString(queryParams.NextBookmark)
			if err != nil {
				return "", fmt.Errorf("not a valid bookmark")
			}

			for splitPart := range strings.SplitSeq(string(decoded), ";") {
				parts := strings.Split(splitPart, ":")
				if len(parts) < 2 {
					continue
				}
				switch parts[0] {
				case "off":
					offset, err = strconv.Atoi(parts[1])
					if err != nil {
						return "", fmt.Errorf("not a valid bookmark")
					}
				case "lim":
					limit, err = strconv.Atoi(parts[1])
					if err != nil {
						return "", fmt.Errorf("not a valid bookmark")
					}
				case "sortM":
					sortMode = parts[1]
				case "sortJP":
					jp, err := base64.StdEncoding.DecodeString(parts[1])
					if err != nil {
						return "", fmt.Errorf("not a valid bookmark")
					}
					jsonPathExpr = string(jp)
				case "sortB":
					sortBy = strings.ReplaceAll(parts[1], ".", "_")
				case "filter":
					fsplit := strings.Split(parts[1], "-")
					if len(fsplit) == 3 {
						field, err := base64.StdEncoding.DecodeString(fsplit[0])
						if err != nil {
							continue
						}
						value, err := base64.StdEncoding.DecodeString(fsplit[2])
						if err != nil {
							continue
						}
						operand, err := strconv.Atoi(fsplit[1])
						if err != nil {
							continue
						}
						fo := resources.FilterOption{
							Field:           string(field),
							FilterOperation: resources.FilterOperation(operand),
							Value:           string(value),
						}
						tx = FilterOperandToWhereClause(fo, tx)
						nextBookmark += fmt.Sprintf("filter:%s-%d-%s;",
							base64.StdEncoding.EncodeToString([]byte(field)),
							operand,
							base64.StdEncoding.EncodeToString([]byte(value)))
					}
				}
				if sortMode != "" && sortBy != "" {
					if jsonPathExpr != "" {
						orderClause := buildJsonPathOrderClause(sortBy, jsonPathExpr, "")
						if sortMode == "desc" {
							tx = tx.Clauses(clause.OrderBy{Expression: gorm.Expr(orderClause + " DESC NULLS LAST")})
						} else {
							tx = tx.Clauses(clause.OrderBy{Expression: gorm.Expr(orderClause + " ASC NULLS FIRST")})
						}
					} else {
						tx = tx.Order(sortBy + " " + sortMode)
					}
				}
			}

			nextBookmark += fmt.Sprintf("off:%d;lim:%d;", offset+limit, limit)
			if queryParams.Sort.SortField != "" {
				sortBy = queryParams.Sort.SortField
				if queryParams.Sort.JsonPathExpr != "" {
					nextBookmark += fmt.Sprintf("sortM:%s;sortJP:%s;sortB:%s;", sortMode,
						base64.StdEncoding.EncodeToString([]byte(queryParams.Sort.JsonPathExpr)), sortBy)
				} else {
					nextBookmark += fmt.Sprintf("sortM:%s;sortB:%s;", sortMode, sortBy)
				}
			}
		}
	}

	tx = applyExtraOpts(tx, extraOpts)
	if offset > 0 {
		tx = tx.Offset(offset)
	}

	if exhaustiveRun {
		res := tx.WithContext(ctx).Preload(clause.Associations).FindInBatches(&elems, limit, func(_ *gorm.DB, _ int) error {
			for _, elem := range elems {
				applyFunc(elem)
			}
			return nil
		})
		return "", res.Error
	}

	tx = tx.Offset(offset).Limit(limit + 1)
	rs := tx.WithContext(ctx).Preload(clause.Associations).Find(&elems)
	if rs.Error != nil {
		return "", rs.Error
	}

	hasMore := len(elems) > limit
	if hasMore {
		elems = elems[:limit]
	}
	for _, elem := range elems {
		applyFunc(elem)
	}
	if !hasMore {
		return "", nil
	}
	return base64.RawURLEncoding.EncodeToString([]byte(nextBookmark)), nil
}

func (q *postgresDBQuerier[E]) SelectExists(ctx context.Context, queryID string, queryCol *string) (bool, *E, error) {
	col := q.primaryKeyColumn
	if queryCol != nil && *queryCol != "" {
		col = *queryCol
	}
	var elem E
	tx := q.Table(q.tableName).WithContext(ctx).Preload(clause.Associations).Limit(1).
		Find(&elem, fmt.Sprintf("%s = ?", col), queryID)
	if tx.Error != nil {
		return false, nil, tx.Error
	}
	if tx.RowsAffected == 0 {
		return false, nil, nil
	}
	return true, &elem, nil
}

func (q *postgresDBQuerier[E]) Insert(ctx context.Context, elem *E, _ string) (*E, error) {
	tx := q.Table(q.tableName).WithContext(ctx).Create(elem)
	if tx.Error != nil {
		return nil, tx.Error
	}
	return elem, nil
}

func (q *postgresDBQuerier[E]) Update(ctx context.Context, elem *E, elemID string) (*E, error) {
	tx := q.Session(&gorm.Session{FullSaveAssociations: true}).
		Table(q.tableName).WithContext(ctx).
		Where(fmt.Sprintf("%s = ?", q.primaryKeyColumn), elemID).
		Save(elem)
	if tx.Error != nil {
		return nil, tx.Error
	}
	if tx.RowsAffected != 1 {
		return nil, gorm.ErrRecordNotFound
	}
	return elem, nil
}

func (q *postgresDBQuerier[E]) Delete(ctx context.Context, elemID string) error {
	tx := q.Table(q.tableName).WithContext(ctx).
		Delete(nil, q.Where(fmt.Sprintf("%s = ?", q.primaryKeyColumn), elemID))
	if tx.Error != nil {
		return tx.Error
	}
	if tx.RowsAffected != 1 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// FilterOperandToWhereClause translates a resources.FilterOption into a GORM WHERE clause.
// Postgres-only: ILIKE is used directly (no SQLite fallback).
func FilterOperandToWhereClause(f resources.FilterOption, tx *gorm.DB) *gorm.DB {
	if strings.Contains(f.Field, ".") {
		f.Field = strings.ReplaceAll(f.Field, ".", "_")
	}
	switch f.FilterOperation {
	case resources.StringEqual:
		return tx.Where(fmt.Sprintf("%s = ?", f.Field), f.Value)
	case resources.StringEqualIgnoreCase:
		return tx.Where(fmt.Sprintf("%s ILIKE ?", f.Field), f.Value)
	case resources.StringNotEqual:
		return tx.Where(fmt.Sprintf("%s <> ?", f.Field), f.Value)
	case resources.StringNotEqualIgnoreCase:
		return tx.Where(fmt.Sprintf("%s NOT ILIKE ?", f.Field), f.Value)
	case resources.StringContains:
		return tx.Where(fmt.Sprintf("%s LIKE ?", f.Field), "%"+f.Value+"%")
	case resources.StringContainsIgnoreCase:
		return tx.Where(fmt.Sprintf("%s ILIKE ?", f.Field), "%"+f.Value+"%")
	case resources.StringNotContains:
		return tx.Where(fmt.Sprintf("%s NOT LIKE ?", f.Field), "%"+f.Value+"%")
	case resources.StringNotContainsIgnoreCase:
		return tx.Where(fmt.Sprintf("%s NOT ILIKE ?", f.Field), "%"+f.Value+"%")
	case resources.StringArrayContains:
		return tx.Where(fmt.Sprintf("%s::jsonb @> ?::jsonb", f.Field), fmt.Sprintf(`["%s"]`, f.Value))
	case resources.StringArrayContainsIgnoreCase:
		return tx.Where(fmt.Sprintf("%s::text ILIKE ?", f.Field), `%"`+f.Value+`"%`)
	case resources.StringIn:
		vals := splitNonEmpty(f.Value)
		if len(vals) == 0 {
			return tx
		}
		return tx.Where(fmt.Sprintf("%s IN ?", f.Field), vals)
	case resources.StringInIgnoreCase:
		vals := splitNonEmpty(f.Value)
		if len(vals) == 0 {
			return tx
		}
		lower := make([]string, len(vals))
		for i, v := range vals {
			lower[i] = strings.ToLower(v)
		}
		return tx.Where(fmt.Sprintf("LOWER(%s) IN ?", f.Field), lower)
	case resources.StringNotIn:
		vals := splitNonEmpty(f.Value)
		if len(vals) == 0 {
			return tx
		}
		return tx.Where(fmt.Sprintf("%s NOT IN ?", f.Field), vals)
	case resources.StringNotInIgnoreCase:
		vals := splitNonEmpty(f.Value)
		if len(vals) == 0 {
			return tx
		}
		lower := make([]string, len(vals))
		for i, v := range vals {
			lower[i] = strings.ToLower(v)
		}
		return tx.Where(fmt.Sprintf("LOWER(%s) NOT IN ?", f.Field), lower)
	case resources.DateEqual:
		return tx.Where(fmt.Sprintf("%s = ?", f.Field), f.Value)
	case resources.DateBefore:
		return tx.Where(fmt.Sprintf("%s < ?", f.Field), f.Value)
	case resources.DateAfter:
		return tx.Where(fmt.Sprintf("%s > ?", f.Field), f.Value)
	case resources.NumberEqual:
		return tx.Where(fmt.Sprintf("%s = ?", f.Field), f.Value)
	case resources.NumberNotEqual:
		return tx.Where(fmt.Sprintf("%s <> ?", f.Field), f.Value)
	case resources.NumberLessThan:
		return tx.Where(fmt.Sprintf("%s < ?", f.Field), f.Value)
	case resources.NumberLessOrEqualThan:
		return tx.Where(fmt.Sprintf("%s <= ?", f.Field), f.Value)
	case resources.NumberGreaterThan:
		return tx.Where(fmt.Sprintf("%s > ?", f.Field), f.Value)
	case resources.NumberGreaterOrEqualThan:
		return tx.Where(fmt.Sprintf("%s >= ?", f.Field), f.Value)
	case resources.EnumEqual:
		return tx.Where(fmt.Sprintf("%s = ?", f.Field), f.Value)
	case resources.EnumNotEqual:
		return tx.Where(fmt.Sprintf("%s <> ?", f.Field), f.Value)
	case resources.EnumIn:
		vals := splitNonEmpty(f.Value)
		if len(vals) == 0 {
			return tx
		}
		return tx.Where(fmt.Sprintf("%s IN ?", f.Field), vals)
	case resources.JsonPathExpression:
		return tx.Where(fmt.Sprintf("%s @@ ?::jsonpath", f.Field), f.Value)
	default:
		return tx
	}
}

func splitNonEmpty(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func convertJsonPathToPostgresPath(jsonPath string) string {
	jsonPath = strings.TrimPrefix(jsonPath, "$.")
	jsonPath = strings.TrimPrefix(jsonPath, "$[")
	jsonPath = strings.TrimSuffix(jsonPath, "]")
	parts := strings.Split(jsonPath, ".")
	for i, p := range parts {
		p = strings.TrimSuffix(p, "[0]")
		p = strings.TrimSuffix(p, "[last]")
		parts[i] = strings.ReplaceAll(p, "'", "''")
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func buildJsonPathOrderClause(field, jsonPath, _ string) string {
	for _, ch := range field {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '_' || ch == '-') {
			return ""
		}
	}
	pgPath := convertJsonPathToPostgresPath(jsonPath)
	parts := strings.Split(strings.Trim(pgPath, "{}"), ",")
	var operatorPath string
	if len(parts) > 1 {
		operatorPath = field
		for _, p := range parts[:len(parts)-1] {
			operatorPath += " -> '" + p + "'"
		}
		operatorPath += " -> '" + parts[len(parts)-1] + "'"
	} else {
		operatorPath = field + " -> '" + parts[0] + "'"
	}
	textPath := fmt.Sprintf("%s #>> '%s'", field, pgPath)
	return fmt.Sprintf(
		"CASE "+
			"WHEN jsonb_typeof(%s) = 'number' THEN lpad(((%s)::numeric)::text, 20, '0') "+
			"WHEN %s ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}' THEN to_char((%s)::timestamp, 'YYYY-MM-DD HH24:MI:SS.US') "+
			"ELSE %s "+
			"END",
		operatorPath, operatorPath, textPath, textPath, textPath,
	)
}
