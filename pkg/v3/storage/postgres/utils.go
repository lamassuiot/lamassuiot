package postgres

import (
	"fmt"

	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/resources"
	gorm_logrus "github.com/onrik/gorm-logrus"
	log "github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func CreatePostgresDBConnection(cfg config.PostgresPSEConfig, database string) (*gorm.DB, error) {
	dbLogrus := logger.Default.LogMode(logger.Silent)
	if log.GetLevel() >= log.DebugLevel {
		dbLogrus = gorm_logrus.New()
		dbLogrus.LogMode(logger.Info)
	}

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=disable", cfg.Hostname, cfg.Username, cfg.Password, database, cfg.Port)
	fmt.Println(dsn)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: dbLogrus,
	})

	return db, err
}

func CheckAndCreateTable[E any](db *gorm.DB, tableName string, primaryKeyColumn string, model E) (*postgresDBQuerier[E], error) {
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

func (db *postgresDBQuerier[E]) SelectAll(queryParams *resources.QueryParameters, extraOpts *map[string]interface{}, exhaustiveRun bool, applyFunc func(elem *E)) (string, error) {
	var elems []E
	db.Table(db.tableName).FindInBatches(&elems, 100, func(tx *gorm.DB, batch int) error {
		for _, elem := range elems {
			// batch processing found records
			applyFunc(&elem)
		}

		log.Tracef("iterating batch %d. Number of records in batch: %d", batch, tx.RowsAffected)

		// returns error will stop future batches
		return nil
	})

	return "nil", nil
}

func (db *postgresDBQuerier[E]) SelectByID(id string) (*E, error) {
	var elem E
	fmt.Println("---------------------")
	fmt.Println("=====================")
	fmt.Println("---------------------")
	tx := db.First(&elem, fmt.Sprintf("%s = ?", db.primaryKeyColumn), id)
	if err := tx.Error; err != nil {
		return nil, err
	}

	return &elem, nil
}

func (db *postgresDBQuerier[E]) Exists(elemID string) (bool, error) {
	var elem E
	tx := db.First(&elem, fmt.Sprintf("%s = ?", db.primaryKeyColumn), elemID)
	if err := tx.Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, nil
		}

		return false, err
	}

	return true, nil
}

func (db *postgresDBQuerier[E]) Insert(elem E, elemID string) (*E, error) {
	tx := db.Create(elem)
	if err := tx.Error; err != nil {
		return nil, err
	}

	return db.SelectByID(elemID)
}

func (db *postgresDBQuerier[E]) Update(elem E, elemID string) (*E, error) {
	tx := db.Save(&elem)
	if err := tx.Error; err != nil {
		return nil, err
	}

	return db.SelectByID(elemID)
}

func getElements[E any](db *gorm.DB, page int, pageSize int, filters map[string]interface{}) ([]E, error) {
	var elems []E

	tx := db.Offset(page * pageSize).Limit(pageSize).Find(&elems)
	if err := tx.Error; err != nil {
		return nil, err
	}

	return elems, nil
}
