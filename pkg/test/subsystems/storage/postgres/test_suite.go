package postgres_test

import (
	"fmt"
	"log"

	"github.com/lamassuiot/lamassuiot/v2/pkg/config"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"
)

type PostgresSuite struct {
	dbName        string
	DB            *gorm.DB
	cleanupDocker func() error
}

func BeforeSuite(dbName string) (config.PostgresPSEConfig, PostgresSuite) {
	cleaner, conf, err := RunPostgresDocker([]string{dbName})
	if err != nil {
		log.Fatal(err)
	}

	conStr := fmt.Sprintf("host=%s port=%d user=%s dbname=%s password=%s sslmode=disable",
		conf.Hostname,
		conf.Port,
		conf.Username,
		dbName,
		conf.Password,
	)

	gdb, _ := gorm.Open(postgres.Open(conStr), &gorm.Config{
		Logger: gormLogger.Discard,
	})

	return *conf, PostgresSuite{
		cleanupDocker: cleaner,
		DB:            gdb,
		dbName:        dbName,
	}
}

func (st *PostgresSuite) AfterSuite() {
	st.cleanupDocker()
}

func (st *PostgresSuite) BeforeEach() error {
	// clear db tables before each test
	var tables []string
	if err := st.DB.Table("information_schema.tables").Where("table_schema = ?", "public").Pluck("table_name", &tables).Error; err != nil {
		panic(err)
	}

	for _, table := range tables {
		tx := st.DB.Exec(fmt.Sprintf("TRUNCATE TABLE  %s;", table))
		err := tx.Error
		if err != nil {
			return err
		}
	}

	return nil
}
