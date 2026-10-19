package postgres

import (
	"context"
	"embed"
	"encoding"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
	lconfig "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/config"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/migrations"
	"github.com/pressly/goose/v3"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	gormlogger "gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
	"gorm.io/plugin/opentelemetry/tracing"
)

var identifierRegex = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// safeColumn turns a field name into a quoted column reference. Field names can
// originate from user input (query params or a decoded bookmark), so dots are
// normalized to underscores and anything that is not a plain identifier is
// rejected instead of being concatenated into the SQL.
func safeColumn(name string) (clause.Column, error) {
	name = strings.ReplaceAll(name, ".", "_")
	if !identifierRegex.MatchString(name) {
		return clause.Column{}, fmt.Errorf("invalid column name")
	}
	return clause.Column{Name: name}, nil
}

// columnEquals builds a "column = value" condition. The column goes through
// safeColumn and is quoted, so it is never formatted into the SQL as is.
func columnEquals(name string, value any) (clause.Expr, error) {
	col, err := safeColumn(name)
	if err != nil {
		return clause.Expr{}, err
	}
	return clause.Expr{SQL: "? = ?", Vars: []any{col, value}}, nil
}

// plainOrderColumn builds a safe ORDER BY column clause for a plain column.
func plainOrderColumn(sortBy, sortMode string) (clause.OrderByColumn, error) {
	col, err := safeColumn(sortBy)
	if err != nil {
		return clause.OrderByColumn{}, err
	}
	mode := strings.ToLower(sortMode)
	if mode != "asc" && mode != "desc" {
		return clause.OrderByColumn{}, fmt.Errorf("invalid sort mode")
	}
	return clause.OrderByColumn{Column: col, Desc: mode == "desc"}, nil
}

//go:embed migrations/**
var embedMigrations embed.FS

// GetEmbeddedMigrations returns the embedded migrations filesystem
func GetEmbeddedMigrations() embed.FS {
	return embedMigrations
}

// registeredPlugins holds GORM plugins to be registered on every new DB connection.
// Call RegisterGORMPlugin during init to inject plugins from outside this module
// (e.g. the authz SDK plugin) without creating a circular module dependency.
var registeredPlugins []gorm.Plugin

// RegisterGORMPlugin adds a GORM plugin that will be registered on every DB
// connection created by CreatePostgresDBConnection. Must be called before any
// storage operations (typically from an init() or a builder registration).
func RegisterGORMPlugin(p gorm.Plugin) {
	registeredPlugins = append(registeredPlugins, p)
}

func CreatePostgresDBConnection(logger *logrus.Entry, cfg lconfig.PostgresPSEConfig, schema string) (*gorm.DB, error) {
	dbLogger := &GormLogger{
		logger: logger,
	}

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=pki port=%d search_path=%s sslmode=disable", cfg.Hostname, cfg.Username, cfg.Password, cfg.Port, schema)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: dbLogger,
	})

	if err != nil {
		return nil, err
	}

	// Set search_path for this connection
	db.Exec(fmt.Sprintf("SET search_path TO %s", schema))

	// Add OTel Tracing
	if err = db.Use(tracing.NewPlugin()); err != nil {
		return nil, err
	}

	for _, p := range registeredPlugins {
		if err = db.Use(p); err != nil {
			return nil, fmt.Errorf("register GORM plugin %q: %w", p.Name(), err)
		}
	}

	return db, nil
}

func TableQuery[E any](log *logrus.Entry, db *gorm.DB, tableName string, primaryKeyColumn string, model E) (*DBQuerier[E], error) {
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
	// Get current schema from search_path
	var schemaName string
	db.Raw("SELECT current_schema()").Scan(&schemaName)

	log.Infof("Planing migrations for schema: %s", schemaName)
	lMig := log.WithField("migrations", schemaName)

	migrationsDir := filepath.Join("migrations", schemaName)
	migrationsFS, err := fs.Sub(embedMigrations, migrationsDir)
	if err != nil {
		lMig.Fatalf("could not obtain migrations subdirectory: %s", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("could not get db connection: %s", err)
	}
	// Reset migrations to avoid conflicts between different
	// schemas migrations (this is to prevent go based migrations from being registered multiple times for different schemas)
	goose.ResetGlobalMigrations()

	migrations.RegisterGoMigrations(schemaName)
	m, err := goose.NewProvider(goose.DialectPostgres, sqlDB, migrationsFS)
	if err != nil {
		lMig.Warnf("could not create migrator: %s", err)
		return nil
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

type DBQuerier[E any] struct {
	*gorm.DB
	tableName        string
	primaryKeyColumn string
	// uniqueColumns identify a row and are appended to every paged ORDER BY so
	// that offset pagination is deterministic. Defaults to the primary key.
	uniqueColumns []string
}

func newPostgresDBQuerier[E any](db *gorm.DB, tableName string, primaryKeyColumn string) DBQuerier[E] {
	return DBQuerier[E]{
		DB:               db,
		tableName:        tableName,
		primaryKeyColumn: primaryKeyColumn,
		uniqueColumns:    []string{primaryKeyColumn},
	}
}

type GormExtraOps struct {
	Query           interface{}
	AdditionalWhere []interface{}
	Joins           []string
}

func applyExtraOpts(tx *gorm.DB, extraOpts []GormExtraOps) *gorm.DB {
	for _, join := range extraOpts {
		for _, j := range join.Joins {
			tx = tx.Joins(j)
		}
	}

	for _, whereQuery := range extraOpts {
		tx = tx.Where(whereQuery.Query, whereQuery.AdditionalWhere...)
	}

	return tx
}

func (db *DBQuerier[E]) Count(ctx context.Context, extraOpts []GormExtraOps) (int, error) {
	var count int64
	tx := db.Table(db.tableName).WithContext(ctx)

	tx = applyExtraOpts(tx, extraOpts)

	tx.Count(&count)
	if err := tx.Error; err != nil {
		return -1, err
	}

	return int(count), nil
}

func (db *DBQuerier[E]) CountFiltered(ctx context.Context, filters []resources.FilterOption, extraOpts []GormExtraOps) (int, error) {
	var count int64
	tx := db.Table(db.tableName).WithContext(ctx)

	for _, filter := range filters {
		tx = FilterOperandToWhereClause(filter, tx)
	}

	tx = applyExtraOpts(tx, extraOpts)

	tx.Count(&count)
	if err := tx.Error; err != nil {
		return -1, err
	}

	return int(count), nil
}

// pageState holds everything needed to fetch one page of results. It is built
// either from the request query params (first page) or from a bookmark
// (following pages), and encodes the bookmark for the next page.
type pageState struct {
	offset  int
	limit   int
	sort    pageSort
	filters []resources.FilterOption
}

// pageSort is the ordering of a page. When jsonPath is set, field is a JSONB
// column and rows are sorted by the value found at that path.
type pageSort struct {
	field    string
	mode     string
	jsonPath string
}

func newPageState(queryParams *resources.QueryParameters) (pageState, error) {
	page := pageState{limit: resources.DefaultPageSize}
	if queryParams == nil {
		return page, nil
	}
	if queryParams.NextBookmark != "" {
		return decodeBookmark(queryParams.NextBookmark)
	}

	if queryParams.PageSize > 0 {
		page.limit = min(queryParams.PageSize, resources.MaxPageSize)
	}
	if queryParams.Sort.SortField != "" {
		page.sort = pageSort{
			field:    queryParams.Sort.SortField,
			mode:     string(queryParams.Sort.SortMode),
			jsonPath: queryParams.Sort.JsonPathExpr,
		}
		if page.sort.mode == "" {
			page.sort.mode = string(resources.SortModeAsc)
		}
	}
	page.filters = queryParams.Filters
	return page, nil
}

func decodeBookmark(bookmark string) (pageState, error) {
	errInvalid := fmt.Errorf("not a valid bookmark")
	page := pageState{limit: resources.DefaultPageSize}

	decoded, err := base64.RawURLEncoding.DecodeString(bookmark)
	if err != nil {
		return page, errInvalid
	}

	for part := range strings.SplitSeq(string(decoded), ";") {
		if part == "" {
			continue
		}
		key, val, ok := strings.Cut(part, ":")
		if !ok {
			return page, errInvalid
		}
		switch key {
		case "off":
			page.offset, err = strconv.Atoi(val)
			if err != nil || page.offset < 0 {
				return page, errInvalid
			}
		case "lim":
			page.limit, err = strconv.Atoi(val)
			if err != nil || page.limit <= 0 {
				return page, errInvalid
			}
			// bookmarks issued before the page size cap may carry a larger limit
			page.limit = min(page.limit, resources.MaxPageSize)
		case "sortM":
			page.sort.mode = val
		case "sortB":
			page.sort.field = val
		case "sortJP":
			jp, err := base64.StdEncoding.DecodeString(val)
			if err != nil {
				return page, errInvalid
			}
			page.sort.jsonPath = string(jp)
		case "filter":
			filterSplit := strings.Split(val, "-")
			if len(filterSplit) != 3 {
				continue
			}
			field, err := base64.StdEncoding.DecodeString(filterSplit[0])
			if err != nil {
				continue
			}
			operand, err := strconv.Atoi(filterSplit[1])
			if err != nil {
				continue
			}
			value, err := base64.StdEncoding.DecodeString(filterSplit[2])
			if err != nil {
				continue
			}
			page.filters = append(page.filters, resources.FilterOption{
				Field:           string(field),
				FilterOperation: resources.FilterOperation(operand),
				Value:           string(value),
			})
		}
	}

	// A sort is only meaningful with both a field and a mode
	if page.sort.field == "" || page.sort.mode == "" {
		page.sort = pageSort{}
	}
	return page, nil
}

// nextBookmark encodes the bookmark pointing to the page after this one,
// keeping the same sort and filters.
func (p pageState) nextBookmark() string {
	var b strings.Builder
	fmt.Fprintf(&b, "off:%d;lim:%d;", p.offset+p.limit, p.limit)
	if p.sort.field != "" {
		fmt.Fprintf(&b, "sortM:%s;", p.sort.mode)
		if p.sort.jsonPath != "" {
			fmt.Fprintf(&b, "sortJP:%s;", base64.StdEncoding.EncodeToString([]byte(p.sort.jsonPath)))
		}
		fmt.Fprintf(&b, "sortB:%s;", p.sort.field)
	}
	for _, f := range p.filters {
		fmt.Fprintf(&b, "filter:%s-%d-%s;", base64.StdEncoding.EncodeToString([]byte(f.Field)), f.FilterOperation, base64.StdEncoding.EncodeToString([]byte(f.Value)))
	}
	return base64.RawURLEncoding.EncodeToString([]byte(b.String()))
}

// orderBy builds the ORDER BY clause for the sort. Field and JSON path are
// validated again here (beyond the controller whitelist), as they can also come
// from a decoded bookmark; the column is quoted and the path bound as a parameter.
func (s pageSort) orderBy() (clause.OrderBy, error) {
	if s.jsonPath != "" {
		expr, err := buildJsonPathOrderExpr(s.field, s.jsonPath, s.mode)
		if err != nil {
			return clause.OrderBy{}, err
		}
		return clause.OrderBy{Expression: expr}, nil
	}

	col, err := plainOrderColumn(s.field, s.mode)
	if err != nil {
		return clause.OrderBy{}, err
	}
	return clause.OrderBy{Columns: []clause.OrderByColumn{col}}, nil
}

// withUniqueOrder appends the querier's unique columns to the given ORDER BY
// (nil when the request has no sort). Without them, rows sharing the same sort
// value, or every row when there is no sort at all, have no defined order in
// PostgreSQL and offset pagination can repeat or skip rows between pages.
func (db *DBQuerier[E]) withUniqueOrder(orderBy *clause.OrderBy) clause.OrderBy {
	unique := make([]clause.OrderByColumn, len(db.uniqueColumns))
	for i, name := range db.uniqueColumns {
		unique[i] = clause.OrderByColumn{Column: clause.Column{Table: clause.CurrentTable, Name: name}}
	}

	switch {
	case orderBy == nil:
		return clause.OrderBy{Columns: unique}
	case orderBy.Expression != nil:
		// GORM renders either the expression or the columns, never both, so the
		// unique columns are appended to the expression itself
		sql := "?" + strings.Repeat(", ?", len(unique))
		vars := []any{orderBy.Expression}
		for _, col := range unique {
			vars = append(vars, col.Column)
		}
		return clause.OrderBy{Expression: clause.Expr{SQL: sql, Vars: vars}}
	default:
		return clause.OrderBy{Columns: append(orderBy.Columns, unique...)}
	}
}

func (db *DBQuerier[E]) SelectAll(ctx context.Context, queryParams *resources.QueryParameters, extraOpts []GormExtraOps, exhaustiveRun bool, applyFunc func(elem E)) (string, error) {
	var elems []E

	page, err := newPageState(queryParams)
	if err != nil {
		return "", err
	}
	offset, limit := page.offset, page.limit

	tx := db.Table(db.tableName)
	for _, filter := range page.filters {
		tx = FilterOperandToWhereClause(filter, tx)
	}
	var orderBy *clause.OrderBy
	if page.sort.field != "" {
		sortOrder, err := page.sort.orderBy()
		if err != nil {
			return "", err
		}
		orderBy = &sortOrder
	}

	tx = applyExtraOpts(tx, extraOpts)

	if exhaustiveRun {
		// The requested sort is ignored: exhaustive runs always walk rows in
		// unique column order, which keeps them safe against rows changing
		// while iterating (see selectAllInBatches)
		return "", db.selectAllInBatches(ctx, tx, offset, limit, applyFunc)
	} else {
		tx = tx.Clauses(db.withUniqueOrder(orderBy)).Offset(offset).Limit(limit + 1)
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

		// No bookmark when there are no more records, nor for requests without
		// query params, which have always been limited to a single page
		if !hasMore || queryParams == nil {
			return "", nil
		}

		return page.nextBookmark(), nil
	}
}

// selectAllInBatches walks every row matching tx in batches, ordered by the
// querier's unique columns, fetching each batch with a keyset condition
// ((unique cols) > (last row's values)) instead of an offset. Callers may update
// rows while iterating (e.g. moving certificates out of the filtered status),
// which would shift an offset and skip rows; a keyset is not affected. The
// initial offset (from a bookmark) only applies to the first batch.
func (db *DBQuerier[E]) selectAllInBatches(ctx context.Context, tx *gorm.DB, offset, batchSize int, applyFunc func(elem E)) error {
	cols := make([]any, len(db.uniqueColumns))
	for i, name := range db.uniqueColumns {
		cols[i] = clause.Column{Table: clause.CurrentTable, Name: name}
	}
	placeholders := "(?" + strings.Repeat(", ?", len(cols)-1) + ")"
	order := db.withUniqueOrder(nil)
	base := tx.Session(&gorm.Session{})

	var last []any
	for {
		var batch []E
		q := base.WithContext(ctx).Preload(clause.Associations).Clauses(order).Limit(batchSize)
		if last == nil {
			q = q.Offset(offset)
		} else {
			q = q.Where(clause.Expr{SQL: placeholders + " > " + placeholders, Vars: append(append([]any{}, cols...), last...)})
		}
		res := q.Find(&batch)
		if res.Error != nil {
			return res.Error
		}

		for _, elem := range batch {
			applyFunc(elem)
		}

		if len(batch) < batchSize {
			return nil
		}

		lastRow := reflect.ValueOf(&batch[len(batch)-1]).Elem()
		last = make([]any, len(db.uniqueColumns))
		for i, name := range db.uniqueColumns {
			field := res.Statement.Schema.LookUpField(name)
			if field == nil {
				return fmt.Errorf("unique column %q not found in %s", name, res.Statement.Schema.Name)
			}
			last[i], _ = field.ValueOf(ctx, lastRow)
		}
	}
}

// Selects first element from DB. if queryCol is empty or nil, the primary key column
// defined in the creation process, is used.
func (db *DBQuerier[E]) SelectExists(ctx context.Context, queryID string, queryCol *string) (bool, *E, error) {
	searchCol := db.primaryKeyColumn
	if queryCol != nil && *queryCol != "" {
		searchCol = *queryCol
	}

	cond, err := columnEquals(searchCol, queryID)
	if err != nil {
		return false, nil, err
	}

	var elem E
	tx := db.Table(db.tableName).WithContext(ctx).Preload(clause.Associations).Limit(1).Find(&elem, cond)
	if tx.Error != nil {
		return false, nil, tx.Error
	}

	if tx.RowsAffected == 0 {
		return false, nil, nil // No record found, but no error
	}

	return true, &elem, nil
}

func (db *DBQuerier[E]) Insert(ctx context.Context, elem *E, elemID string) (*E, error) {
	tx := db.Table(db.tableName).WithContext(ctx).Create(elem)
	if err := tx.Error; err != nil {
		return nil, err
	}

	return elem, nil
}

func (db *DBQuerier[E]) Update(ctx context.Context, elem *E, elemID string) (*E, error) {
	cond, err := columnEquals(db.primaryKeyColumn, elemID)
	if err != nil {
		return nil, err
	}

	tx := db.Session(&gorm.Session{FullSaveAssociations: true}).Table(db.tableName).WithContext(ctx).Where(cond).Save(elem)
	if err := tx.Error; err != nil {
		return nil, err
	}

	if tx.RowsAffected != 1 {
		return nil, gorm.ErrRecordNotFound
	}

	return elem, nil
}

func (db *DBQuerier[E]) Delete(ctx context.Context, elemID string) error {
	cond, err := columnEquals(db.primaryKeyColumn, elemID)
	if err != nil {
		return err
	}

	tx := db.Table(db.tableName).WithContext(ctx).Delete(nil, cond)
	if err := tx.Error; err != nil {
		return err
	}

	if tx.RowsAffected != 1 {
		return gorm.ErrRecordNotFound
	}

	return nil
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

// likeEscaper escapes the LIKE/ILIKE wildcards so user values are matched
// literally. Backslash is PostgreSQL's default LIKE escape character.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

func escapeLike(value string) string {
	return likeEscaper.Replace(value)
}

// jsonStringArray encodes value as a single-element JSON array, so quotes and
// other special characters in it cannot alter the resulting JSON document.
func jsonStringArray(value string) string {
	b, _ := json.Marshal([]string{value})
	return string(b)
}

func FilterOperandToWhereClause(filter resources.FilterOption, tx *gorm.DB) *gorm.DB {
	col, err := safeColumn(filter.Field)
	if err != nil {
		_ = tx.AddError(err)
		return tx
	}

	switch filter.FilterOperation {
	case resources.StringEqual:
		return tx.Where("? = ?", col, filter.Value)
	case resources.StringEqualIgnoreCase:
		return tx.Where("? ILIKE ?", col, escapeLike(filter.Value))
	case resources.StringNotEqual:
		return tx.Where("? <> ?", col, filter.Value)
	case resources.StringNotEqualIgnoreCase:
		return tx.Where("? NOT ILIKE ?", col, escapeLike(filter.Value))
	case resources.StringContains:
		return tx.Where("? LIKE ?", col, "%"+escapeLike(filter.Value)+"%")
	case resources.StringContainsIgnoreCase:
		return tx.Where("? ILIKE ?", col, "%"+escapeLike(filter.Value)+"%")
	case resources.StringArrayContains:
		// Arrays serialized into text columns need a cast before using the JSON containment operator.
		return tx.Where("?::jsonb @> ?::jsonb", col, jsonStringArray(filter.Value))
	case resources.StringArrayContainsIgnoreCase:
		return tx.Where("?::text ILIKE ?", col, "%\""+escapeLike(filter.Value)+"\"%")
	case resources.StringNotContains:
		return tx.Where("? NOT LIKE ?", col, "%"+escapeLike(filter.Value)+"%")
	case resources.StringNotContainsIgnoreCase:
		return tx.Where("? NOT ILIKE ?", col, "%"+escapeLike(filter.Value)+"%")
	case resources.StringIn:
		values := splitNonEmpty(filter.Value)
		if len(values) == 0 {
			return tx
		}
		return tx.Where("? IN ?", col, values)
	case resources.StringInIgnoreCase:
		values := splitNonEmpty(filter.Value)
		if len(values) == 0 {
			return tx
		}
		lowerValues := make([]string, len(values))
		for i, v := range values {
			lowerValues[i] = strings.ToLower(v)
		}
		return tx.Where("LOWER(?) IN ?", col, lowerValues)
	case resources.StringNotIn:
		values := splitNonEmpty(filter.Value)
		if len(values) == 0 {
			return tx
		}
		return tx.Where("? NOT IN ?", col, values)
	case resources.StringNotInIgnoreCase:
		values := splitNonEmpty(filter.Value)
		if len(values) == 0 {
			return tx
		}
		lowerValues := make([]string, len(values))
		for i, v := range values {
			lowerValues[i] = strings.ToLower(v)
		}
		return tx.Where("LOWER(?) NOT IN ?", col, lowerValues)
	case resources.DateEqual:
		return tx.Where("? = ?", col, filter.Value)
	case resources.DateBefore:
		return tx.Where("? < ?", col, filter.Value)
	case resources.DateAfter:
		return tx.Where("? > ?", col, filter.Value)
	case resources.NumberEqual:
		return tx.Where("? = ?", col, filter.Value)
	case resources.NumberNotEqual:
		return tx.Where("? <> ?", col, filter.Value)
	case resources.NumberLessThan:
		return tx.Where("? < ?", col, filter.Value)
	case resources.NumberLessOrEqualThan:
		return tx.Where("? <= ?", col, filter.Value)
	case resources.NumberGreaterThan:
		return tx.Where("? > ?", col, filter.Value)
	case resources.NumberGreaterOrEqualThan:
		return tx.Where("? >= ?", col, filter.Value)
	case resources.EnumEqual:
		return tx.Where("? = ?", col, filter.Value)
	case resources.EnumNotEqual:
		return tx.Where("? <> ?", col, filter.Value)
	case resources.EnumIn:
		values := splitNonEmpty(filter.Value)
		if len(values) == 0 {
			return tx
		}
		return tx.Where("? IN ?", col, values)
	case resources.JsonPathExpression:
		// JSONPath Filtering Security:
		// - Field name validated against whitelist in controller layer
		// - JsonPathExpr (filter.Value) validated with isValidJsonPath() in controller layer
		// - Uses parameterized query (?) which prevents SQL injection
		// - PostgreSQL's @@ operator safely evaluates the jsonpath expression
		return tx.Where("? @@ ?::jsonpath", col, filter.Value)
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

// buildJsonPathOrderExpr builds an ORDER BY expression that sorts by a value
// inside a JSONB column. The column is quoted and the path is bound as a
// parameter (keys are validated beforehand), so nothing user-controlled is
// concatenated into the SQL. The path may originate from user input (query
// params or a decoded bookmark).
func buildJsonPathOrderExpr(field, jsonPath, sortMode string) (clause.Expression, error) {
	col, err := safeColumn(field)
	if err != nil {
		return nil, err
	}
	keys, err := resources.ParseSortJsonPath(jsonPath)
	if err != nil {
		return nil, err
	}

	path := "{" + strings.Join(keys, ",") + "}"

	// Build CASE expression that handles:
	// 1. Numbers - pad for proper text sorting
	// 2. Dates/timestamps - cast to timestamp for proper chronological sorting
	// 3. Text - use as-is
	sql := "CASE " +
		"WHEN jsonb_typeof(? #> ?::text[]) = 'number' THEN lpad(((? #> ?::text[])::numeric)::text, 20, '0') " +
		"WHEN (? #>> ?::text[]) ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}' THEN to_char(((? #>> ?::text[]))::timestamp, 'YYYY-MM-DD HH24:MI:SS.US') " +
		"ELSE (? #>> ?::text[]) " +
		"END"
	if strings.EqualFold(sortMode, "desc") {
		sql += " DESC NULLS LAST"
	} else {
		sql += " ASC NULLS FIRST"
	}

	return gorm.Expr(sql, col, path, col, path, col, path, col, path, col, path), nil
}
