package postgres_test

import (
	"fmt"
	"log"

	"github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/config"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"
)

type PostgresSuite struct {
	dbNames       []string
	DB            map[string]*gorm.DB
	cleanupDocker func() error
}

func BeforeSuite(dbNames []string) (config.PostgresPSEConfig, PostgresSuite) {
	dbs := make(map[string]string)
	for _, dbName := range dbNames {
		dbs[dbName] = ""
	}

	cleaner, conf, err := RunPostgresDocker(dbs)
	if err != nil {
		log.Fatal(err)
	}

	dbMap := make(map[string]*gorm.DB)
	for _, dbName := range dbNames {
		conStr := fmt.Sprintf("host=%s port=%d user=%s dbname=%s password=%s sslmode=disable",
			conf.Hostname,
			conf.Port,
			conf.Username,
			dbName,
			conf.Password,
		)
		dbMap[dbName], _ = gorm.Open(postgres.Open(conStr), &gorm.Config{
			Logger: gormLogger.Discard,
		})
	}

	return *conf, PostgresSuite{
		cleanupDocker: cleaner,
		DB:            dbMap,
		dbNames:       dbNames,
	}
}

func (st *PostgresSuite) AfterSuite() {
	st.cleanupDocker()
}

func (st *PostgresSuite) BeforeEach() error {
	// clear db tables before each test
	for _, dbName := range st.dbNames {
		var tables []string
		if err := st.DB[dbName].Table("information_schema.tables").Where("table_schema = ?", "public").Pluck("table_name", &tables).Error; err != nil {
			panic(err)
		}

		for _, table := range tables {
			tx := st.DB[dbName].Exec(fmt.Sprintf("TRUNCATE TABLE  %s;", table))
			err := tx.Error
			if err != nil {
				return err
			}
		}
	}

	return nil
}
