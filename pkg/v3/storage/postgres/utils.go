package postgres

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/resources"
	gorm_logrus "github.com/onrik/gorm-logrus"
	log "github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gorm_logger "gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
)

func CreatePostgresDBConnection(logger *log.Entry, cfg config.PostgresPSEConfig, database string) (*gorm.DB, error) {
	dbLogrus := gorm_logger.Default.LogMode(gorm_logger.Error)
	if logger.Level >= log.DebugLevel {
		dbLogrus = gorm_logrus.New()
		dbLogrus.LogMode(gorm_logger.Info)
	}

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=disable", cfg.Hostname, cfg.Username, cfg.Password, database, cfg.Port)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: dbLogrus,
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

func (db *postgresDBQuerier[E]) Count() (int, error) {
	var count int64

	tx := db.Table(db.tableName).Count(&count)
	if err := tx.Error; err != nil {
		return -1, err
	}

	return int(count), nil
}

type gormWhereParams struct {
	query     interface{}
	extraArgs []interface{}
}

func (db *postgresDBQuerier[E]) SelectAll(queryParams *resources.QueryParameters, extraOpts []gormWhereParams, exhaustiveRun bool, applyFunc func(elem *E)) (string, error) {
	var elems []E
	tx := db.Table(db.tableName)

	for _, whereQuery := range extraOpts {
		tx = tx.Where(whereQuery.query, whereQuery.extraArgs...)
	}
	//tx.Offset(queryParams.Pagination.Offset)
	//tx.Limit(queryParams.Pagination.PageSize)
	//tx.Order(queryParams.Sort.SortField + " " + string(queryParams.Sort.SortMode))

	tx.FindInBatches(&elems, 100, func(tx *gorm.DB, batch int) error {
		for _, elem := range elems {
			// batch processing found records
			applyFunc(&elem)
		}

		log.Tracef("iterating batch %d. Number of records in batch: %d", batch, tx.RowsAffected)

		// returns error will stop future batches
		return nil
	})
	var bookmark = ""
	if queryParams != nil {
		if queryParams.Pagination.PageSize > 0 {
			bookmark = bookmark + fmt.Sprintf("offset:%d", queryParams.Pagination.PageSize)
		}
	}
	//bookmark = "offset:1"

	return base64.StdEncoding.EncodeToString([]byte(bookmark)), nil
}

// Selects first element from DB. if queryCol is empty or nil, the primary key column
// defined in the creation process, is used.
func (db *postgresDBQuerier[E]) SelectExists(queryID string, queryCol *string) (bool, *E, error) {
	searchCol := db.primaryKeyColumn
	if queryCol != nil && *queryCol != "" {
		searchCol = *queryCol
	}

	var elem E
	tx := db.First(&elem, fmt.Sprintf("%s = ?", searchCol), queryID)
	if err := tx.Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, nil, nil
		}

		return false, nil, err
	}

	return true, &elem, nil
}

func (db *postgresDBQuerier[E]) Insert(elem E, elemID string) (*E, error) {
	tx := db.Create(elem)
	if err := tx.Error; err != nil {
		return nil, err
	}

	_, newElem, err := db.SelectExists(elemID, nil)
	return newElem, err
}

func (db *postgresDBQuerier[E]) Update(elem E, elemID string) (*E, error) {
	tx := db.Save(&elem)
	if err := tx.Error; err != nil {
		return nil, err
	}

	_, newElem, err := db.SelectExists(elemID, nil)
	return newElem, err
}

func (db *postgresDBQuerier[E]) Delete(elemID string) error {
	exists, elem, err := db.SelectExists(elemID, nil)
	if err != nil {
		return err
	}

	if !exists {
		return gorm.ErrRecordNotFound
	}

	tx := db.DB.Delete(&elem)
	if err := tx.Error; err != nil {
		return err
	}

	return nil
}

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

func GenerateBookmark(offset int, limit int) {}
