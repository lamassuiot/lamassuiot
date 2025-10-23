package postgres

import (
	"context"
	"embed"
	"encoding"
	"encoding/base64"
	"fmt"
	"io/fs"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	lconfig "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/config"
	"github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/migrations"
	"github.com/pressly/goose/v3"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	gormlogger "gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
)

//go:embed migrations/**
var embedMigrations embed.FS

// GetEmbeddedMigrations returns the embedded migrations filesystem
func GetEmbeddedMigrations() embed.FS {
	return embedMigrations
}

func CreatePostgresDBConnection(logger *logrus.Entry, cfg lconfig.PostgresPSEConfig, database string) (*gorm.DB, error) {
	dbLogger := &GormLogger{
		logger: logger,
	}

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=disable", cfg.Hostname, cfg.Username, cfg.Password, database, cfg.Port)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: dbLogger,
	})

	return db, err
}

func TableQuery[E any](log *logrus.Entry, db *gorm.DB, tableName string, primaryKeyColumn string, model E) (*postgresDBQuerier[E], error) {
	schema.RegisterSerializer("text", TextSerializer{})
	querier := newPostgresDBQuerier[E](db, tableName, primaryKeyColumn)
	return &querier, nil
}

// TextSerializer string serializer
type TextSerializer struct{}

func (TextSerializer) Scan(ctx context.Context, field *schema.Field, dst reflect.Value, dbValue interface{}) (err error) {
	// Create a new instance of the field type
	fieldValue := reflect.New(field.FieldType).Interface()

	// Check if the fieldValue implements encoding.TextUnmarshaler
	unmarshaler, ok := fieldValue.(encoding.TextUnmarshaler)
	if !ok {
		return fmt.Errorf("field type does not implement encoding.TextUnmarshaler")
	}

	// Convert dbValue to a string or []byte
	var textData []byte
	switch v := dbValue.(type) {
	case string:
		textData = []byte(v)
	case []byte:
		textData = v
	default:
		return fmt.Errorf("unsupported dbValue type: %T", dbValue)
	}

	// Use the UnmarshalText method to populate the field
	if err := unmarshaler.UnmarshalText(textData); err != nil {
		return fmt.Errorf("failed to unmarshal text: %w", err)
	}

	// Set the value back to the destination
	field.ReflectValueOf(ctx, dst).Set(reflect.ValueOf(fieldValue).Elem())
	return nil
}

// Value implements serializer interface
func (TextSerializer) Value(ctx context.Context, field *schema.Field, dst reflect.Value, fieldValue interface{}) (interface{}, error) {
	// Check if fieldValue implements encoding.TextMarshaler
	if marshaler, ok := fieldValue.(encoding.TextMarshaler); ok {
		text, err := marshaler.MarshalText()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal text: %w", err)
		}
		return string(text), nil // Return the text representation as a string
	}

	return nil, fmt.Errorf("fieldValue does not implement encoding.TextMarshaler")
}

type migrator struct {
	db     *gorm.DB
	logger *logrus.Entry
	Goose  *goose.Provider
}

func NewMigrator(log *logrus.Entry, db *gorm.DB) *migrator {
	dbName := db.Migrator().CurrentDatabase()

	log.Infof("Planing migrations")
	lMig := log.WithField("migrations", dbName)

	migrationsDir := filepath.Join("migrations", dbName)
	migrationsFS, err := fs.Sub(embedMigrations, migrationsDir)
	if err != nil {
		lMig.Fatalf("could not obtain migrations subdirectory: %s", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("could not get db connection: %s", err)
	}
	// Reset migrations to avoid conflicts between different
	// databases migrations (this is to prevent go based migrations from being registered multiple times for different databases)
	goose.ResetGlobalMigrations()

	migrations.RegisterGoMigrations(dbName)
	m, err := goose.NewProvider(goose.DialectPostgres, sqlDB, migrationsFS)
	if err != nil {
		lMig.Fatalf("could not create migrator: %s", err)
	}

	return &migrator{
		db:     db,
		logger: lMig,
		Goose:  m,
	}
}

func (migrator *migrator) MigrateToLatest() {
	//based on the current db version, get the target version
	c, t, err := migrator.Goose.GetVersions(context.Background())
	if err != nil {
		migrator.logger.Fatalf("could not get db version: %s", err)
	}

	migrator.logger.Infof("Current version: %d", c)
	migrator.logger.Infof("Target version: %d", t)

	r, err := migrator.Goose.UpTo(context.Background(), t)
	if err != nil {
		migrator.logger.Fatalf("could not migrate db: %s", err)
	}

	migrator.logger.Infof("Migrated %d steps", len(r))
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

type gormExtraOps struct {
	query           interface{}
	additionalWhere []interface{}
	joins           []string
}

func applyExtraOpts(tx *gorm.DB, extraOpts []gormExtraOps) *gorm.DB {
	for _, join := range extraOpts {
		for _, j := range join.joins {
			tx = tx.Joins(j)
		}
	}

	for _, whereQuery := range extraOpts {
		tx = tx.Where(whereQuery.query, whereQuery.additionalWhere...)
	}

	return tx
}

func (db *postgresDBQuerier[E]) Count(ctx context.Context, extraOpts []gormExtraOps) (int, error) {
	var count int64
	tx := db.Table(db.tableName).WithContext(ctx)

	tx = applyExtraOpts(tx, extraOpts)

	tx.Count(&count)
	if err := tx.Error; err != nil {
		return -1, err
	}

	return int(count), nil
}

func (db *postgresDBQuerier[E]) SelectAll(ctx context.Context, queryParams *resources.QueryParameters, extraOpts []gormExtraOps, exhaustiveRun bool, applyFunc func(elem E)) (string, error) {
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
				sortBy = strings.ReplaceAll(queryParams.Sort.SortField, ".", "_")
				nextBookmark = nextBookmark + fmt.Sprintf("sortM:%s;sortB:%s;", sortMode, sortBy)
				tx = tx.Order(sortBy + " " + sortMode)
			}

			for _, filter := range queryParams.Filters {
				tx = FilterOperandToWhereClause(filter, tx)
				nextBookmark = nextBookmark + fmt.Sprintf("filter:%s-%d-%s;", base64.StdEncoding.EncodeToString([]byte(filter.Field)), filter.FilterOperation, base64.StdEncoding.EncodeToString([]byte(filter.Value)))
			}

		} else {
			nextBookmark = ""
			decodedBookmark, err := base64.RawURLEncoding.DecodeString(queryParams.NextBookmark)
			if err != nil {
				return "", fmt.Errorf("not a valid bookmark")
			}

			splits := strings.SplitSeq(string(decodedBookmark), ";")

			for splitPart := range splits {
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
					sortBy = strings.ReplaceAll(queryPart[1], ".", "_")
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

						nextBookmark = nextBookmark + fmt.Sprintf("filter:%s-%d-%s;", base64.StdEncoding.EncodeToString([]byte(field)), operand, base64.StdEncoding.EncodeToString([]byte(value)))
					}
				}
				if sortMode != "" && sortBy != "" {
					tx = tx.Order(sortBy + " " + sortMode)
				}
			}
			nextBookmark = nextBookmark + fmt.Sprintf("off:%d;lim:%d;", offset+limit, limit)
			if queryParams.Sort.SortField != "" {
				sortBy = queryParams.Sort.SortField
				nextBookmark = nextBookmark + fmt.Sprintf("sortM:%s;sortB:%s;", sortMode, sortBy)
			}
		}
	}

	tx = applyExtraOpts(tx, extraOpts)

	if offset > 0 {
		tx.Offset(offset)
	}

	if exhaustiveRun {
		res := tx.WithContext(ctx).Preload(clause.Associations).FindInBatches(&elems, limit, func(tx *gorm.DB, batch int) error {
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
		tx.Limit(limit + 1)
		rs := tx.WithContext(ctx).Preload(clause.Associations).Find(&elems)

		if rs.Error != nil {
			return "", rs.Error
		}

		// Check if we got more than the requested limit
		hasMore := len(elems) > limit

		// Trim elems to the requested limit
		if hasMore {
			elems = elems[:limit] // Keep only the requested limit
		}

		for _, elem := range elems {
			// batch processing found records
			applyFunc(elem)
		}

		if !hasMore {
			// no more records to fetch. Reset nextBookmark to empty string
			return "", nil
		}

		return base64.RawURLEncoding.EncodeToString([]byte(nextBookmark)), nil
	}
}

// Selects first element from DB. if queryCol is empty or nil, the primary key column
// defined in the creation process, is used.
func (db *postgresDBQuerier[E]) SelectExists(ctx context.Context, queryID string, queryCol *string) (bool, *E, error) {
	searchCol := db.primaryKeyColumn
	if queryCol != nil && *queryCol != "" {
		searchCol = *queryCol
	}

	var elem E
	tx := db.Table(db.tableName).WithContext(ctx).Preload(clause.Associations).Limit(1).Find(&elem, fmt.Sprintf("%s = ?", searchCol), queryID)
	if tx.Error != nil {
		return false, nil, tx.Error
	}

	if tx.RowsAffected == 0 {
		return false, nil, nil // No record found, but no error
	}

	return true, &elem, nil
}

func (db *postgresDBQuerier[E]) Insert(ctx context.Context, elem *E, elemID string) (*E, error) {
	tx := db.Table(db.tableName).WithContext(ctx).Create(elem)
	if err := tx.Error; err != nil {
		return nil, err
	}

	return elem, nil
}

func (db *postgresDBQuerier[E]) Update(ctx context.Context, elem *E, elemID string) (*E, error) {
	tx := db.Session(&gorm.Session{FullSaveAssociations: true}).Table(db.tableName).WithContext(ctx).Where(fmt.Sprintf("%s = ?", db.primaryKeyColumn), elemID).Save(elem)
	if err := tx.Error; err != nil {
		return nil, err
	}

	if tx.RowsAffected != 1 {
		return nil, gorm.ErrRecordNotFound
	}

	return elem, nil
}

func (db *postgresDBQuerier[E]) Delete(ctx context.Context, elemID string) error {
	tx := db.Table(db.tableName).WithContext(ctx).Delete(nil, db.Where(fmt.Sprintf("%s = ?", db.primaryKeyColumn), elemID))
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
	case resources.StringEqualIgnoreCase:
		return tx.Where(fmt.Sprintf("%s ILIKE ?", filter.Field), filter.Value)
	case resources.StringNotEqual:
		return tx.Where(fmt.Sprintf("%s <> ?", filter.Field), filter.Value)
	case resources.StringNotEqualIgnoreCase:
		return tx.Where(fmt.Sprintf("%s NOT ILIKE ?", filter.Field), filter.Value)
	case resources.StringContains:
		return tx.Where(fmt.Sprintf("%s LIKE ?", filter.Field), fmt.Sprintf("%%%s%%", filter.Value))
	case resources.StringContainsIgnoreCase:
		return tx.Where(fmt.Sprintf("%s ILIKE ?", filter.Field), fmt.Sprintf("%%%s%%", filter.Value))
	case resources.StringArrayContains:
		// return tx.Where(fmt.Sprintf("? = ANY(%s)", filter.Field), filter.Value)
		return tx.Where(fmt.Sprintf("%s LIKE ?", filter.Field), fmt.Sprintf("%%%s%%", filter.Value))
	case resources.StringArrayContainsIgnoreCase:
		// return tx.Where(fmt.Sprintf("? = ANY(%s)", filter.Field), filter.Value)
		return tx.Where(fmt.Sprintf("%s ILIKE ?", filter.Field), fmt.Sprintf("%%%s%%", filter.Value))
	case resources.StringNotContains:
		return tx.Where(fmt.Sprintf("%s NOT LIKE ?", filter.Field), fmt.Sprintf("%%%s%%", filter.Value))
	case resources.StringNotContainsIgnoreCase:
		return tx.Where(fmt.Sprintf("%s NOT ILIKE ?", filter.Field), fmt.Sprintf("%%%s%%", filter.Value))
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

func NewGormLogger(logger *logrus.Entry) *GormLogger {
	return &GormLogger{
		logger: logger,
	}
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
	le := helpers.ConfigureLogger(ctx, l.logger)
	le.Infof(str, rest...)
}

func (l *GormLogger) Warn(ctx context.Context, str string, rest ...interface{}) {
	le := helpers.ConfigureLogger(ctx, l.logger)
	le.Warnf(str, rest...)
}

func (l *GormLogger) Error(ctx context.Context, str string, rest ...interface{}) {
	le := helpers.ConfigureLogger(ctx, l.logger)
	le.Errorf(str, rest...)
}

func (l *GormLogger) Trace(ctx context.Context, begin time.Time, fc func() (sql string, rowsAffected int64), err error) {
	le := helpers.ConfigureLogger(ctx, l.logger)
	sql, rows := fc()
	if err != nil {
		le.Errorf("Took: %s, Err:%s, SQL: %s, AffectedRows: %d", time.Since(begin).String(), err, sql, rows)
	} else {
		le.Tracef("Took: %s, SQL: %s, AffectedRows: %d", time.Since(begin).String(), sql, rows)
	}

}
