package postgres

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/go-gormigrate/gormigrate/v2"
	"github.com/lamassuiot/lamassuiot/v2/core/config"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/resources"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
)

type DBVersion struct {
	CreationTS    time.Time
	SchemaVersion int
}

type DBVersionMigrationNode struct {
	next       *DBVersionMigrationNode
	migrations []*gormigrate.Migration
	label      string
	id         int
}

type DBMigrationList struct {
	head *DBVersionMigrationNode
}

func (l *DBMigrationList) Insert(id int, label string, migrations []*gormigrate.Migration) {
	list := &DBVersionMigrationNode{migrations: migrations, id: id, label: label, next: nil}
	if l.head == nil {
		l.head = list
	} else {
		p := l.head
		for p.next != nil {
			p = p.next
		}
		p.next = list
	}
}

func (n *DBVersionMigrationNode) MigrationPlanTo(targetMigration int) []*DBVersionMigrationNode {
	nodes := []*DBVersionMigrationNode{}

	node := n
	for {
		nodes = append(nodes, node)
		if node.next != nil {
			node = node.next
		} else {
			break
		}
	}

	return nodes
}

func CreatePostgresDBConnection(logger *logrus.Entry, cfg config.PostgresPSEConfig, database string) (*gorm.DB, error) {
	dbLogger := &GormLogger{
		logger: logger,
	}

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=disable", cfg.Hostname, cfg.Username, cfg.Password, database, cfg.Port)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: dbLogger,
	})

	return db, err
}

func CheckAndCreateTable[E any](db *gorm.DB, tableName string, primaryKeyColumn string, model E) (*postgresDBQuerier[E], error) {
	schema.RegisterSerializer("json", JSONSerializer{})

	err := db.Table(tableName).AutoMigrate(model)
	if err != nil {
		return nil, err
	}

	querier := newPostgresDBQuerier[E](db, tableName, primaryKeyColumn)
	return &querier, nil
}

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

func (db *postgresDBQuerier[E]) Count(extraOpts []gormWhereParams) (int, error) {
	var count int64
	tx := db.Table(db.tableName)
	for _, whereQuery := range extraOpts {
		tx = tx.Where(whereQuery.query, whereQuery.extraArgs...)
	}

	tx.Count(&count)
	if err := tx.Error; err != nil {
		return -1, err
	}

	return int(count), nil
}

type gormWhereParams struct {
	query     interface{}
	extraArgs []interface{}
}

func (db *postgresDBQuerier[E]) SelectAll(queryParams *resources.QueryParameters, extraOpts []gormWhereParams, exhaustiveRun bool, applyFunc func(elem E)) (string, error) {
	var elems []E
	tx := db.Table(db.tableName)

	offset := 0
	limit := 15

	var sortMode string
	var sortBy string

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
				sortBy = queryParams.Sort.SortField
				nextBookmark = nextBookmark + fmt.Sprintf("sortM:%s;sortB:%s", sortMode, sortBy)
				tx = tx.Order(sortBy + " " + sortMode)
			}

			for _, filter := range queryParams.Filters {
				tx = FilterOperandToWhereClause(filter, tx)
				nextBookmark = nextBookmark + fmt.Sprintf("filter:%s-%d-%s", base64.StdEncoding.EncodeToString([]byte(filter.Field)), filter.FilterOperation, base64.StdEncoding.EncodeToString([]byte(filter.Value)))
			}

		} else {
			nextBookmark = ""
			decodedBookmark, err := base64.StdEncoding.DecodeString(queryParams.NextBookmark)
			if err != nil {
				return "", fmt.Errorf("not a valid bookmark")
			}

			splits := strings.Split(string(decodedBookmark), ";")

			for _, splitPart := range splits {
				queryPart := strings.Split(splitPart, ":")
				switch queryPart[0] {
				case "off":
					offset, err = strconv.Atoi(queryPart[1])
					if err != nil {
						return "", fmt.Errorf("not a valid bookmark")
					}
				case "lim":
					limit, err = strconv.Atoi(queryPart[1])
					if err != nil {
						return "", fmt.Errorf("not a valid bookmark")
					}
				case "sortM":
					sortMode = queryPart[1]
					if err != nil {
						return "", fmt.Errorf("not a valid bookmark")
					}
				case "sortB":
					sortBy = queryPart[1]
					if err != nil {
						return "", fmt.Errorf("not a valid bookmark")
					}
				case "filter":
					filter := queryPart[1]
					if err != nil {
						return "", fmt.Errorf("not a valid bookmark")
					}
					filterSplit := strings.Split(filter, "-")
					if len(filterSplit) == 3 {
						field, err := base64.StdEncoding.DecodeString(filterSplit[0])
						if err != nil {
							continue
						}
						value, err := base64.StdEncoding.DecodeString(filterSplit[2])
						if err != nil {
							continue
						}

						operand, err := strconv.Atoi(filterSplit[1])
						if err != nil {
							continue
						}

						tx = FilterOperandToWhereClause(resources.FilterOption{
							Field:           string(field),
							FilterOperation: resources.FilterOperation(operand),
							Value:           string(value),
						}, tx)
					}
				}
				if sortMode != "" && sortBy != "" {
					tx = tx.Order(sortBy + " " + sortMode)
				}
			}
			nextBookmark = fmt.Sprintf("off:%d;lim:%d;", offset+limit, limit)
			if queryParams.Sort.SortField != "" {
				sortBy = queryParams.Sort.SortField
				nextBookmark = nextBookmark + fmt.Sprintf("sortM:%s;sortB:%s", sortMode, sortBy)
			}
		}
	}
	for _, whereQuery := range extraOpts {
		tx = tx.Where(whereQuery.query, whereQuery.extraArgs...)
	}

	if offset > 0 {
		tx.Offset(offset)
	}

	if exhaustiveRun {
		res := tx.FindInBatches(&elems, limit, func(tx *gorm.DB, batch int) error {
			for _, elem := range elems {
				applyFunc(elem)
			}

			return nil
		})
		if res.Error != nil {
			return "", res.Error
		}

		return "", nil
	} else {
		tx.Offset(offset)
		tx.Limit(limit)
		rs := tx.Find(&elems)
		for _, elem := range elems {
			// batch processing found records
			applyFunc(elem)
		}

		if rs.Error != nil {
			return "", rs.Error
		}

		if rs.RowsAffected == 0 {
			return "", nil
		}

		return base64.StdEncoding.EncodeToString([]byte(nextBookmark)), nil
	}
}

// Selects first element from DB. if queryCol is empty or nil, the primary key column
// defined in the creation process, is used.
func (db *postgresDBQuerier[E]) SelectExists(queryID string, queryCol *string) (bool, *E, error) {
	searchCol := db.primaryKeyColumn
	if queryCol != nil && *queryCol != "" {
		searchCol = *queryCol
	}

	var elem E
	tx := db.Table(db.tableName).First(&elem, fmt.Sprintf("%s = ?", searchCol), queryID)
	if err := tx.Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, nil, nil
		}

		return false, nil, err
	}

	return true, &elem, nil
}

func (db *postgresDBQuerier[E]) Insert(elem *E, elemID string) (*E, error) {
	tx := db.Table(db.tableName).Create(elem)
	if err := tx.Error; err != nil {
		return nil, err
	}

	return elem, nil
}

func (db *postgresDBQuerier[E]) Update(elem *E, elemID string) (*E, error) {
	tx := db.Table(db.tableName).Where(fmt.Sprintf("%s = ?", db.primaryKeyColumn), elemID).Updates(elem)
	if err := tx.Error; err != nil {
		return nil, err
	}

	if tx.RowsAffected != 1 {
		return nil, gorm.ErrRecordNotFound
	}

	return elem, nil
}

func (db *postgresDBQuerier[E]) Delete(elemID string) error {
	tx := db.Table(db.tableName).Delete(nil, db.Where(fmt.Sprintf("%s = ?", db.primaryKeyColumn), elemID))
	if err := tx.Error; err != nil {
		return err
	}

	if tx.RowsAffected != 1 {
		return gorm.ErrRecordNotFound
	}

	return nil
}

func FilterOperandToWhereClause(filter resources.FilterOption, tx *gorm.DB) *gorm.DB {
	if strings.Contains(filter.Field, ".") {
		filter.Field = strings.ReplaceAll(filter.Field, ".", "_")
	}

	switch filter.FilterOperation {
	case resources.StringEqual:
		return tx.Where(fmt.Sprintf("%s = ?", filter.Field), filter.Value)
	case resources.StringNotEqual:
		return tx.Where(fmt.Sprintf("%s <> ?", filter.Field), filter.Value)
	case resources.StringContains:
		return tx.Where(fmt.Sprintf("%s LIKE ?", filter.Field), fmt.Sprintf("%%%s%%", filter.Value))
	case resources.StringArrayContains:
		// return tx.Where(fmt.Sprintf("? = ANY(%s)", filter.Field), filter.Value)
		return tx.Where(fmt.Sprintf("%s LIKE ?", filter.Field), fmt.Sprintf("%%%s%%", filter.Value))
	case resources.StringNotContains:
		return tx.Where(fmt.Sprintf("%s NOT LIKE ?", filter.Field), fmt.Sprintf("%%%s%%", filter.Value))
	case resources.DateEqual:
		return tx.Where(fmt.Sprintf("%s = ?", filter.Field), filter.Value)
	case resources.DateBefore:
		return tx.Where(fmt.Sprintf("%s < ?", filter.Field), filter.Value)
	case resources.DateAfter:
		return tx.Where(fmt.Sprintf("%s > ?", filter.Field), filter.Value)
	case resources.NumberEqual:
		return tx.Where(fmt.Sprintf("%s = ?", filter.Field), filter.Value)
	case resources.NumberNotEqual:
		return tx.Where(fmt.Sprintf("%s <> ?", filter.Field), filter.Value)
	case resources.NumberLessThan:
		return tx.Where(fmt.Sprintf("%s < ?", filter.Field), filter.Value)
	case resources.NumberLessOrEqualThan:
		return tx.Where(fmt.Sprintf("%s <= ?", filter.Field), filter.Value)
	case resources.NumberGreaterThan:
		return tx.Where(fmt.Sprintf("%s > ?", filter.Field), filter.Value)
	case resources.NumberGreaterOrEqualThan:
		return tx.Where(fmt.Sprintf("%s >= ?", filter.Field), filter.Value)
	case resources.EnumEqual:
		return tx.Where(fmt.Sprintf("%s = ?", filter.Field), filter.Value)
	case resources.EnumNotEqual:
		return tx.Where(fmt.Sprintf("%s <> ?", filter.Field), filter.Value)
	default:
		return tx
	}
}

// // string_array json serializer
// type StringArraySerializer struct{}

// func (StringArraySerializer) Scan(ctx context.Context, field *schema.Field, dst reflect.Value, dbValue interface{}) (err error) {
// 	switch dbValue.(type) {
// 	case []pq.StringArray:
// 		sarray := dbValue.(pq.StringArray)
// 		var sa []string = sarray
// 		src := reflect.ValueOf(sa)
// 		field.ReflectValueOf(ctx, dst).Set(src)
// 		return nil

// 	default:
// 		return fmt.Errorf("invalid value type")
// 	}

// }

// // Value implements serializer interface
// func (StringArraySerializer) Value(ctx context.Context, field *schema.Field, dst reflect.Value, fieldValue interface{}) (interface{}, error) {
// 	return pq.Array(fieldValue), nil
// }

// JSONSerializer json serializer
type JSONSerializer struct {
}

// Scan implements serializer interface
func (JSONSerializer) Scan(ctx context.Context, field *schema.Field, dst reflect.Value, dbValue interface{}) (err error) {
	fieldValue := reflect.New(field.FieldType)
	var decodeVal string
	switch dbValue.(type) {
	case string:
		decodeVal = dbValue.(string)
	default:
		return fmt.Errorf("invalid value type")
	}

	err = json.Unmarshal([]byte(decodeVal), fieldValue.Interface())
	if err != nil {
		return err
	}

	field.ReflectValueOf(ctx, dst).Set(fieldValue.Elem())
	return
}

// Value implements serializer interface
func (JSONSerializer) Value(ctx context.Context, field *schema.Field, dst reflect.Value, fieldValue interface{}) (interface{}, error) {
	return json.Marshal(fieldValue)
}

// Logrus GORM iface implementation
// https://www.soberkoder.com/go-gorm-logging/
type GormLogger struct {
	logger *logrus.Entry
}

func (l *GormLogger) LogMode(lvl gormlogger.LogLevel) gormlogger.Interface {
	newlogger := *l
	return &newlogger
}

func (l *GormLogger) Info(ctx context.Context, str string, rest ...interface{}) {
	l.logger.Infof(str, rest...)
}

func (l *GormLogger) Warn(ctx context.Context, str string, rest ...interface{}) {
	l.logger.Warnf(str, rest...)
}

func (l *GormLogger) Error(ctx context.Context, str string, rest ...interface{}) {
	l.logger.Errorf(str, rest...)
}

func (l *GormLogger) Trace(ctx context.Context, begin time.Time, fc func() (sql string, rowsAffected int64), err error) {
	sql, rows := fc()
	if err != nil {
		l.logger.Errorf("Took: %s, Err:%s, SQL: %s, AffectedRows: %d", time.Since(begin).String(), err, sql, rows)
	} else {
		l.logger.Tracef("Took: %s, SQL: %s, AffectedRows: %d", time.Since(begin).String(), sql, rows)
	}

}
