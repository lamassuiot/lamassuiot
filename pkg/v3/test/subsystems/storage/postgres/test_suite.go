package postgres_test

import (
	"log"

	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"gorm.io/gorm"
)

var Db *gorm.DB
var cleanupDocker func() error

func BeforeSuite(dbName string) config.PostgresPSEConfig {
	cleaner, conf, err := RunPostgresDocker([]string{dbName})
	if err != nil {
		log.Fatal(err)
	}

	cleanupDocker = cleaner
	return *conf
}

func AfterSuite() {
	cleanupDocker()
}

func BeforeEach() error {
	// clear db tables before each test
	err := Db.Exec(`DROP SCHEMA public CASCADE;CREATE SCHEMA public;`).Error
	return err
}
