//go:build experimental
// +build experimental

package sqlite_test

import (
	"fmt"
	"os"

	"github.com/lamassuiot/lamassuiot/v2/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/storage/sqlite"

	"gorm.io/gorm"
)

type SQLiteSuite struct {
	dbNames []string
	DB      map[string]*gorm.DB
	cleanup func() error
}

func BeforeSuite(cfg config.SQLitePSEConfig, dbNames []string) SQLiteSuite {

	logger := helpers.SetupLogger(config.Trace, "", "")
	dbMap := make(map[string]*gorm.DB)
	for _, dbName := range dbNames {
		dbMap[dbName], _ = sqlite.CreateDBConnection(logger, cfg, dbName)
	}

	cleaner := func() error {
		for _, dbName := range dbNames {
			db, err := dbMap[dbName].DB()
			if err == nil {
				db.Close()
			}

			if !cfg.InMemory {
				dbfile := fmt.Sprintf("%s/%s.db", cfg.DatabasePath, dbName)
				if err := os.Remove(dbfile); err != nil {
					return err
				}
			}
		}
		return nil
	}

	return SQLiteSuite{
		cleanup: cleaner,
		DB:      dbMap,
		dbNames: dbNames,
	}
}

func (st *SQLiteSuite) AfterSuite() {
	st.cleanup()
}

func (st *SQLiteSuite) BeforeEach() error {
	// clear db tables before each test
	for _, dbName := range st.dbNames {
		var tables []string
		if err := st.DB[dbName].Table("sqlite_schema").Where("type = ?", "table").Pluck("name", &tables).Error; err != nil {
			panic(err)
		}

		for _, table := range tables {
			tx := st.DB[dbName].Exec(fmt.Sprintf("DELETE FROM  %s;", table))
			err := tx.Error
			if err != nil {
				return err
			}
		}
	}

	return nil
}
