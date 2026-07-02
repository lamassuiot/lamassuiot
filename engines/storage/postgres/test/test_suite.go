package postgrestest

import (
	"fmt"
	"log"
	"slices"
	"strings"

	"github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/config"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"
)

type PostgresSuite struct {
	schemaNames   []string
	DB            map[string]*gorm.DB
	cleanupDocker func() error
}

func BeforeSuite(schemaNames []string, exposeAsStandardPort bool) (config.PostgresPSEConfig, PostgresSuite) {
	schemas := make(map[string]string)
	for _, schemaName := range schemaNames {
		schemas[schemaName] = ""
	}

	cleaner, conf, err := RunPostgresDocker(schemas, exposeAsStandardPort)
	if err != nil {
		log.Fatal(err)
	}

	dbMap := make(map[string]*gorm.DB)
	for _, schemaName := range schemaNames {
		conStr := fmt.Sprintf("host=%s port=%d user=%s dbname=%s password=%s search_path=%s sslmode=disable",
			conf.Hostname,
			conf.Port,
			conf.Username,
			"pki",
			conf.Password,
			schemaName,
		)
		db, _ := gorm.Open(postgres.Open(conStr), &gorm.Config{
			Logger: gormLogger.Discard,
		})

		// Set search_path for each connection
		db.Exec(fmt.Sprintf("SET search_path TO %s", schemaName))

		dbMap[schemaName] = db
	}

	return *conf, PostgresSuite{
		cleanupDocker: cleaner,
		DB:            dbMap,
		schemaNames:   schemaNames,
	}
}

func (st *PostgresSuite) AfterSuite() {
	st.cleanupDocker()
}

func (st *PostgresSuite) BeforeEach() error {
	// clear db tables before each test
	for _, schemaName := range st.schemaNames {
		var tables []string
		if err := st.DB[schemaName].Raw("SELECT tablename FROM pg_tables WHERE schemaname = ?", schemaName).Pluck("tablename", &tables).Error; err != nil {
			panic(err)
		}

		// Truncate all tables but not the migrations table
		tables = slices.DeleteFunc(tables, func(s string) bool {
			return s == "goose_db_version"
		})

		if len(tables) > 0 {
			// Qualify table names with schema
			qualifiedTables := make([]string, len(tables))
			for i, table := range tables {
				qualifiedTables[i] = fmt.Sprintf("%s.%s", schemaName, table)
			}

			tx := st.DB[schemaName].Exec(fmt.Sprintf("TRUNCATE TABLE %s CASCADE;", strings.Join(qualifiedTables, ", ")))
			err := tx.Error
			if err != nil {
				return err
			}
		}
	}

	return nil
}
