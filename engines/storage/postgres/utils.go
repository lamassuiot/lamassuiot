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
	"sync"
	"time"

	core "github.com/lamassuiot/lamassuiot/core/v3"
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
	"gorm.io/plugin/opentelemetry/tracing"
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

	if err != nil {
		return nil, err
	}

	// Add OTel Tracing
	if err := db.Use(tracing.NewPlugin()); err != nil {
		return nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	maxOpen := cfg.MaxOpenConns
	if maxOpen <= 0 {
		maxOpen = defaultMaxOpenConns
	}
	sqlDB.SetMaxOpenConns(maxOpen)
	sqlDB.SetMaxIdleConns(maxOpen)
	return db, nil
}

const defaultMaxOpenConns = 20

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
	// hasTenantColumn caches whether this table can be tenant-scoped: the Go model exposes a
	// TenantID field, the connection is PostgreSQL (not SQLite), and the physical table
	// actually has a tenant_id column. The last check matters for migration-verification
	// tests, which construct repositories against intermediate, pre-tenant-migration schema
	// snapshots; those must keep behaving as unscoped, single-tenant tables.
	hasTenantColumn bool
}

func newPostgresDBQuerier[E any](db *gorm.DB, tableName string, primaryKeyColumn string) postgresDBQuerier[E] {
	hasTenantColumn := isTenantScopedEntity[E]() && !isSQLite(db) && db.Migrator().HasColumn(tableName, tenantIDColumnName)
	return postgresDBQuerier[E]{
		DB:               db,
		tableName:        tableName,
		primaryKeyColumn: primaryKeyColumn,
		hasTenantColumn:  hasTenantColumn,
	}
}

type gormExtraOps struct {
	query           interface{}
	additionalWhere []interface{}
	joins           []string
}

// tenantIDFieldName is the Go struct field name that every tenant-scoped model must expose.
const tenantIDFieldName = "TenantID"

// tenantIDColumnName is the Postgres column backing tenantIDFieldName.
const tenantIDColumnName = "tenant_id"

// isTenantScopedEntity reports whether E carries a TenantID field and therefore must be
// scoped to the caller's tenant. Control-plane and global models without TenantID are left
// untouched.
func isTenantScopedEntity[E any]() bool {
	var zero E
	t := reflect.TypeOf(zero)
	if t == nil || t.Kind() != reflect.Struct {
		return false
	}
	_, found := t.FieldByName(tenantIDFieldName)
	return found
}

// setTenantID forces the TenantID field of elem (a *E) to tenantID, overriding any value a
// caller may have supplied. This guarantees no tenant_id can be chosen by client input.
func setTenantID(elem any, tenantID string) {
	v := reflect.ValueOf(elem)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	field := v.FieldByName(tenantIDFieldName)
	if field.IsValid() && field.CanSet() && field.Kind() == reflect.String {
		field.SetString(tenantID)
	}
}

// tenantScope resolves the tenant that must scope this operation. ok=false means the entity
// is not tenant-scoped (or the connection is SQLite, which does not support the RLS-backed
// multi-tenancy model and keeps its pre-existing single-tenant behaviour), so the caller must
// proceed without tenant enforcement. When ok=true and err!=nil, the caller must fail closed:
// no tenant-scoped operation is allowed without a validated TenantContext.
func (db *postgresDBQuerier[E]) tenantScope(ctx context.Context) (tenantID string, ok bool, err error) {
	if !db.hasTenantColumn {
		return "", false, nil
	}

	tenantContext, err := core.RequireTenantContext(ctx)
	if err != nil {
		return "", true, err
	}

	return tenantContext.TenantID, true, nil
}

func (db *postgresDBQuerier[E]) tenantIDColumn() string {
	return db.tableName + "." + tenantIDColumnName
}

// withTenantScopedTx runs fn against a *gorm.DB already scoped to ctx. When the operation is
// tenant-scoped it executes inside a transaction with `app.tenant_id` set via SET LOCAL so
// that PostgreSQL RLS policies (USING/WITH CHECK) enforce the same boundary at the database
// layer. Non tenant-scoped operations keep the previous, unscoped behaviour.
func (db *postgresDBQuerier[E]) withTenantScopedTx(ctx context.Context, scoped bool, fn func(tx *gorm.DB) error) error {
	if scoped {
		return WithTenantTransaction(ctx, db.DB, fn)
	}
	return fn(db.DB.WithContext(ctx))
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
	tenantID, scoped, err := db.tenantScope(ctx)
	if err != nil {
		return -1, err
	}

	var count int64
	err = db.withTenantScopedTx(ctx, scoped, func(tx *gorm.DB) error {
		q := tx.Table(db.tableName)
		if scoped {
			q = q.Where(db.tenantIDColumn()+" = ?", tenantID)
		}
		q = applyExtraOpts(q, extraOpts)
		return q.Count(&count).Error
	})
	if err != nil {
		return -1, err
	}

	return int(count), nil
}

func (db *postgresDBQuerier[E]) CountFiltered(ctx context.Context, filters []resources.FilterOption, extraOpts []gormExtraOps) (int, error) {
	tenantID, scoped, err := db.tenantScope(ctx)
	if err != nil {
		return -1, err
	}

	var count int64
	err = db.withTenantScopedTx(ctx, scoped, func(tx *gorm.DB) error {
		q := tx.Table(db.tableName)
		if scoped {
			q = q.Where(db.tenantIDColumn()+" = ?", tenantID)
		}
		for _, filter := range filters {
			q = FilterOperandToWhereClause(filter, q)
		}
		q = applyExtraOpts(q, extraOpts)
		return q.Count(&count).Error
	})
	if err != nil {
		return -1, err
	}

	return int(count), nil
}

func (db *postgresDBQuerier[E]) SelectAll(ctx context.Context, queryParams *resources.QueryParameters, extraOpts []gormExtraOps, exhaustiveRun bool, applyFunc func(elem E)) (string, error) {
	tenantID, scoped, err := db.tenantScope(ctx)
	if err != nil {
		return "", err
	}

	var bookmark string
	err = db.withTenantScopedTx(ctx, scoped, func(tx *gorm.DB) error {
		base := tx.Table(db.tableName)
		if scoped {
			base = base.Where(db.tenantIDColumn()+" = ?", tenantID)
		}
		var innerErr error
		bookmark, innerErr = db.selectAllBody(ctx, base, queryParams, extraOpts, exhaustiveRun, applyFunc)
		return innerErr
	})
	if err != nil {
		return "", err
	}

	return bookmark, nil
}

func (db *postgresDBQuerier[E]) selectAllBody(ctx context.Context, tx *gorm.DB, queryParams *resources.QueryParameters, extraOpts []gormExtraOps, exhaustiveRun bool, applyFunc func(elem E)) (string, error) {
	var elems []E

	offset := 0
	limit := 15

	var sortMode string
	var sortBy string
	var jsonPathExpr string

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
				// JSONPath Sorting Security:
				// - Field name validated against whitelist in controller layer
				// - JsonPathExpr validated with isValidJsonPath() and isSimpleJsonPath() in controller layer
				// - Only simple dot-separated paths allowed for sorting (complex expressions rejected)
				// - Field name re-validated in buildJsonPathOrderClause() for extra safety
				// - Single quotes escaped by convertJsonPathToPostgresPath()
				// - No user input directly concatenated into SQL
				if queryParams.Sort.JsonPathExpr != "" {
					orderClause := buildJsonPathOrderClause(queryParams.Sort.SortField, queryParams.Sort.JsonPathExpr, "")
					nextBookmark = nextBookmark + fmt.Sprintf("sortM:%s;sortJP:%s;sortB:%s;", sortMode, base64.StdEncoding.EncodeToString([]byte(queryParams.Sort.JsonPathExpr)), queryParams.Sort.SortField)
					if sortMode == "desc" {
						tx = tx.Clauses(clause.OrderBy{
							Expression: gorm.Expr(orderClause + " DESC NULLS LAST"),
						})
					} else {
						tx = tx.Clauses(clause.OrderBy{
							Expression: gorm.Expr(orderClause + " ASC NULLS FIRST"),
						})
					}
				} else {
					sortBy = strings.ReplaceAll(queryParams.Sort.SortField, ".", "_")
					nextBookmark = nextBookmark + fmt.Sprintf("sortM:%s;sortB:%s;", sortMode, sortBy)
					tx = tx.Order(sortBy + " " + sortMode)
				}
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
				case "sortJP":
					jp, err := base64.StdEncoding.DecodeString(queryPart[1])
					if err != nil {
						return "", fmt.Errorf("not a valid bookmark")
					}
					jsonPathExpr = string(jp)
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
					if jsonPathExpr != "" {
						orderClause := buildJsonPathOrderClause(sortBy, jsonPathExpr, "")
						if sortMode == "desc" {
							tx = tx.Clauses(clause.OrderBy{
								Expression: gorm.Expr(orderClause + " DESC NULLS LAST"),
							})
						} else {
							tx = tx.Clauses(clause.OrderBy{
								Expression: gorm.Expr(orderClause + " ASC NULLS FIRST"),
							})
						}
					} else {
						tx = tx.Order(sortBy + " " + sortMode)
					}
				}
			}
			nextBookmark = nextBookmark + fmt.Sprintf("off:%d;lim:%d;", offset+limit, limit)
			if queryParams.Sort.SortField != "" {
				sortBy = queryParams.Sort.SortField
				if queryParams.Sort.JsonPathExpr != "" {
					nextBookmark = nextBookmark + fmt.Sprintf("sortM:%s;sortJP:%s;sortB:%s;", sortMode, base64.StdEncoding.EncodeToString([]byte(queryParams.Sort.JsonPathExpr)), sortBy)
				} else {
					nextBookmark = nextBookmark + fmt.Sprintf("sortM:%s;sortB:%s;", sortMode, sortBy)
				}
			}
		}
	}

	tx = applyExtraOpts(tx, extraOpts)

	if exhaustiveRun {
		sorted := sortBy != "" || (queryParams != nil && queryParams.Sort.SortField != "")
		return "", db.selectAllInBatches(ctx, tx, offset, limit, sorted, applyFunc)
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

var batchSchemaCache sync.Map

// batchKeyFields returns the model fields that identify a row within the (tenant-scoped)
// query: the gorm primary key fields, which may be composite (events: tenant_id, event_type),
// or the querier's primary key column when the model declares none (va_role, kms_keys).
func (db *postgresDBQuerier[E]) batchKeyFields() ([]*schema.Field, error) {
	s, err := schema.Parse(new(E), &batchSchemaCache, db.NamingStrategy)
	if err != nil {
		return nil, err
	}

	if len(s.PrimaryFields) > 0 {
		return s.PrimaryFields, nil
	}

	if field := s.LookUpField(db.primaryKeyColumn); field != nil {
		return []*schema.Field{field}, nil
	}

	return nil, fmt.Errorf("table %s: no key column to paginate on", db.tableName)
}

// selectAllInBatches reads every row matching tx in batches of limit rows, skipping the
// first offset rows. gorm's FindInBatches is not used because it requires a single primary
// key and fails with "primary key required" on composite keys or models without one.
// Unsorted runs paginate by key (keyset) ordered by the key columns; sorted runs keep the
// requested order, tie-broken by the key columns, and paginate by offset.
func (db *postgresDBQuerier[E]) selectAllInBatches(ctx context.Context, tx *gorm.DB, offset int, limit int, sorted bool, applyFunc func(elem E)) error {
	keyFields, err := db.batchKeyFields()
	if err != nil {
		return err
	}

	if limit <= 0 {
		limit = 15
	}

	keyColumns := make([]string, 0, len(keyFields))
	for _, field := range keyFields {
		keyColumns = append(keyColumns, tx.Statement.Quote(clause.Column{Table: db.tableName, Name: field.DBName}))
		tx = tx.Order(clause.OrderByColumn{Column: clause.Column{Table: db.tableName, Name: field.DBName}})
	}
	base := tx.WithContext(ctx).Preload(clause.Associations).Session(&gorm.Session{})

	var lastKey []any
	for batch := 0; ; batch++ {
		q := base.Limit(limit)
		switch {
		case sorted:
			q = q.Offset(offset + batch*limit)
		case lastKey == nil:
			q = q.Offset(offset)
		default:
			placeholders := strings.TrimSuffix(strings.Repeat("?, ", len(lastKey)), ", ")
			q = q.Where(fmt.Sprintf("(%s) > (%s)", strings.Join(keyColumns, ", "), placeholders), lastKey...)
		}

		var elems []E
		if err := q.Find(&elems).Error; err != nil {
			return err
		}

		for _, elem := range elems {
			applyFunc(elem)
		}

		if len(elems) < limit {
			return nil
		}

		last := reflect.ValueOf(&elems[len(elems)-1]).Elem()
		lastKey = make([]any, 0, len(keyFields))
		for _, field := range keyFields {
			value, _ := field.ValueOf(ctx, last)
			lastKey = append(lastKey, value)
		}
	}
}

// Selects first element from DB. if queryCol is empty or nil, the primary key column
// defined in the creation process, is used.
func (db *postgresDBQuerier[E]) SelectExists(ctx context.Context, queryID string, queryCol *string) (bool, *E, error) {
	searchCol := db.primaryKeyColumn
	if queryCol != nil && *queryCol != "" {
		searchCol = *queryCol
	}

	tenantID, scoped, err := db.tenantScope(ctx)
	if err != nil {
		return false, nil, err
	}

	var elem E
	var rowsAffected int64
	err = db.withTenantScopedTx(ctx, scoped, func(tx *gorm.DB) error {
		q := tx.Table(db.tableName).Preload(clause.Associations).Limit(1)
		if scoped {
			q = q.Where(db.tenantIDColumn()+" = ?", tenantID)
		}
		result := q.Find(&elem, fmt.Sprintf("%s = ?", searchCol), queryID)
		rowsAffected = result.RowsAffected
		return result.Error
	})
	if err != nil {
		return false, nil, err
	}

	if rowsAffected == 0 {
		return false, nil, nil // No record found, but no error
	}

	return true, &elem, nil
}

func (db *postgresDBQuerier[E]) Insert(ctx context.Context, elem *E, elemID string) (*E, error) {
	tenantID, scoped, err := db.tenantScope(ctx)
	if err != nil {
		return nil, err
	}
	if scoped {
		setTenantID(elem, tenantID)
	}

	err = db.withTenantScopedTx(ctx, scoped, func(tx *gorm.DB) error {
		return tx.Table(db.tableName).Create(elem).Error
	})
	if err != nil {
		return nil, err
	}

	return elem, nil
}

func (db *postgresDBQuerier[E]) Update(ctx context.Context, elem *E, elemID string) (*E, error) {
	tenantID, scoped, err := db.tenantScope(ctx)
	if err != nil {
		return nil, err
	}
	if scoped {
		// No arbitrary tenant reassignment: the context tenant always wins.
		setTenantID(elem, tenantID)
	}

	var rowsAffected int64
	err = db.withTenantScopedTx(ctx, scoped, func(tx *gorm.DB) error {
		q := tx.Session(&gorm.Session{FullSaveAssociations: true}).Table(db.tableName).Where(fmt.Sprintf("%s = ?", db.primaryKeyColumn), elemID)
		if scoped {
			q = q.Where(db.tenantIDColumn()+" = ?", tenantID)
		}
		// NOTE: intentionally uses Select("*").Updates(...) instead of Save(...). GORM's
		// Save() falls back to `INSERT ... ON CONFLICT DO UPDATE` whenever the WHERE clause
		// matches zero rows, which would silently hijack another tenant's row (or create a
		// phantom row for an unknown ID) instead of failing. Updates never performs that
		// fallback, so a cross-tenant or non-existent elemID correctly yields zero rows
		// affected below.
		result := q.Select("*").Updates(elem)
		rowsAffected = result.RowsAffected
		return result.Error
	})
	if err != nil {
		return nil, err
	}

	if rowsAffected != 1 {
		return nil, gorm.ErrRecordNotFound
	}

	return elem, nil
}

func (db *postgresDBQuerier[E]) Delete(ctx context.Context, elemID string) error {
	tenantID, scoped, err := db.tenantScope(ctx)
	if err != nil {
		return err
	}

	var rowsAffected int64
	err = db.withTenantScopedTx(ctx, scoped, func(tx *gorm.DB) error {
		q := tx.Table(db.tableName).Where(fmt.Sprintf("%s = ?", db.primaryKeyColumn), elemID)
		if scoped {
			q = q.Where(db.tenantIDColumn()+" = ?", tenantID)
		}
		result := q.Delete(nil)
		rowsAffected = result.RowsAffected
		return result.Error
	})
	if err != nil {
		return err
	}

	if rowsAffected != 1 {
		return gorm.ErrRecordNotFound
	}

	return nil
}

func isSQLite(tx *gorm.DB) bool {
	// Check if the dialector name contains "sqlite"
	return strings.Contains(strings.ToLower(tx.Dialector.Name()), "sqlite")
}

// splitNonEmpty splits a comma-separated string and returns only non-empty trimmed values.
func splitNonEmpty(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func FilterOperandToWhereClause(filter resources.FilterOption, tx *gorm.DB) *gorm.DB {
	if strings.Contains(filter.Field, ".") {
		filter.Field = strings.ReplaceAll(filter.Field, ".", "_")
	}

	// SQLite doesn't support ILIKE, use LIKE instead (case insensitivity is set via PRAGMA)
	ilike := "ILIKE"
	notIlike := "NOT ILIKE"
	if isSQLite(tx) {
		ilike = "LIKE"
		notIlike = "NOT LIKE"
	}

	switch filter.FilterOperation {
	case resources.StringEqual:
		return tx.Where(fmt.Sprintf("%s = ?", filter.Field), filter.Value)
	case resources.StringEqualIgnoreCase:
		return tx.Where(fmt.Sprintf("%s %s ?", filter.Field, ilike), filter.Value)
	case resources.StringNotEqual:
		return tx.Where(fmt.Sprintf("%s <> ?", filter.Field), filter.Value)
	case resources.StringNotEqualIgnoreCase:
		return tx.Where(fmt.Sprintf("%s %s ?", filter.Field, notIlike), filter.Value)
	case resources.StringContains:
		return tx.Where(fmt.Sprintf("%s LIKE ?", filter.Field), fmt.Sprintf("%%%s%%", filter.Value))
	case resources.StringContainsIgnoreCase:
		return tx.Where(fmt.Sprintf("%s %s ?", filter.Field, ilike), fmt.Sprintf("%%%s%%", filter.Value))
	case resources.StringArrayContains:
		if isSQLite(tx) {
			return tx.Where(fmt.Sprintf("%s %s ?", filter.Field, ilike), "%\""+filter.Value+"\"%")
		}
		// Arrays serialized into text columns need a cast before using the JSON containment operator.
		return tx.Where(fmt.Sprintf("%s::jsonb @> ?::jsonb", filter.Field), fmt.Sprintf(`["%s"]`, filter.Value))
	case resources.StringArrayContainsIgnoreCase:
		return tx.Where(fmt.Sprintf("%s::text %s ?", filter.Field, ilike), "%\""+filter.Value+"\"%")
	case resources.StringNotContains:
		return tx.Where(fmt.Sprintf("%s NOT LIKE ?", filter.Field), fmt.Sprintf("%%%s%%", filter.Value))
	case resources.StringNotContainsIgnoreCase:
		return tx.Where(fmt.Sprintf("%s %s ?", filter.Field, notIlike), fmt.Sprintf("%%%s%%", filter.Value))
	case resources.StringIn:
		values := splitNonEmpty(filter.Value)
		if len(values) == 0 {
			return tx
		}
		return tx.Where(fmt.Sprintf("%s IN ?", filter.Field), values)
	case resources.StringInIgnoreCase:
		values := splitNonEmpty(filter.Value)
		if len(values) == 0 {
			return tx
		}
		lowerValues := make([]string, len(values))
		for i, v := range values {
			lowerValues[i] = strings.ToLower(v)
		}
		return tx.Where(fmt.Sprintf("LOWER(%s) IN ?", filter.Field), lowerValues)
	case resources.StringNotIn:
		values := splitNonEmpty(filter.Value)
		if len(values) == 0 {
			return tx
		}
		return tx.Where(fmt.Sprintf("%s NOT IN ?", filter.Field), values)
	case resources.StringNotInIgnoreCase:
		values := splitNonEmpty(filter.Value)
		if len(values) == 0 {
			return tx
		}
		lowerValues := make([]string, len(values))
		for i, v := range values {
			lowerValues[i] = strings.ToLower(v)
		}
		return tx.Where(fmt.Sprintf("LOWER(%s) NOT IN ?", filter.Field), lowerValues)
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
	case resources.EnumIn:
		values := splitNonEmpty(filter.Value)
		if len(values) == 0 {
			return tx
		}
		return tx.Where(fmt.Sprintf("%s IN ?", filter.Field), values)
	case resources.JsonPathExpression:
		// JSONPath Filtering Security:
		// - Field name validated against whitelist in controller layer
		// - JsonPathExpr (filter.Value) validated with isValidJsonPath() in controller layer
		// - Uses parameterized query (?) which prevents SQL injection
		// - PostgreSQL's @@ operator safely evaluates the jsonpath expression
		return tx.Where(fmt.Sprintf("%s @@ ?::jsonpath", filter.Field), filter.Value)
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

// convertJsonPathToPostgresPath converts a simple JSONPath expression (e.g., "$.foo.bar")
// to PostgreSQL JSONB path format (e.g., "{foo,bar}")
// Note: This function only handles simple dot-separated paths, not complex expressions
// Input should already be validated by controller layer
func convertJsonPathToPostgresPath(jsonPath string) string {
	// Remove leading "$." if present
	jsonPath = strings.TrimPrefix(jsonPath, "$.")
	// Remove leading "$[" if present (for array access)
	jsonPath = strings.TrimPrefix(jsonPath, "$[")
	// Remove trailing "]" if present
	jsonPath = strings.TrimSuffix(jsonPath, "]")

	// Split by "." and sanitize each part
	parts := strings.Split(jsonPath, ".")
	// Escape single quotes in each part to prevent SQL injection
	for i, part := range parts {
		// Remove any remaining brackets for simple array access like $.tags[0]
		part = strings.TrimSuffix(part, "[0]")
		part = strings.TrimSuffix(part, "[last]")
		parts[i] = strings.ReplaceAll(part, "'", "''")
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// buildJsonPathOrderClause generates a PostgreSQL ORDER BY clause for JSONB fields
// that handles numeric, date/timestamp, and text values correctly
// Note: Input validation should be performed at controller layer before calling this
// This function only supports simple dot-separated paths for sorting
func buildJsonPathOrderClause(field, jsonPath, sortMode string) string {
	// Security: Validate that field name contains only safe characters
	// Field names should be validated by controller layer, but double-check here
	// Allow only alphanumeric, underscore, and hyphen
	for _, char := range field {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '_' || char == '-') {
			// If field name contains unsafe characters, return empty string
			// This will cause a SQL error rather than injection
			return ""
		}
	}

	pgPath := convertJsonPathToPostgresPath(jsonPath)
	// Extract the last element for the -> operator
	parts := strings.Split(strings.Trim(pgPath, "{}"), ",")
	var operatorPath string
	if len(parts) > 1 {
		// For nested paths like {env,config}, use -> for intermediate and ->> for last
		operatorPath = field
		for i := 0; i < len(parts)-1; i++ {
			// parts[i] is already sanitized (quotes escaped) by convertJsonPathToPostgresPath
			operatorPath += " -> '" + parts[i] + "'"
		}
		operatorPath += " -> '" + parts[len(parts)-1] + "'"
	} else {
		// For simple paths like {priority}
		operatorPath = field + " -> '" + parts[0] + "'"
	}

	textPath := fmt.Sprintf("%s #>> '%s'", field, pgPath)

	// Build CASE expression that handles:
	// 1. Numbers - pad for proper text sorting
	// 2. Dates/timestamps - cast to timestamp for proper chronological sorting
	// 3. Text - use as-is
	return fmt.Sprintf(
		"CASE "+
			"WHEN jsonb_typeof(%s) = 'number' THEN lpad(((%s)::numeric)::text, 20, '0') "+
			"WHEN %s ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}' THEN to_char((%s)::timestamp, 'YYYY-MM-DD HH24:MI:SS.US') "+
			"ELSE %s "+
			"END",
		operatorPath,
		operatorPath,
		textPath,
		textPath,
		textPath,
	)
}
