package transport

import (
	"fmt"

	postgresconfig "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/config"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func openDirect(cfg postgresconfig.PostgresPSEConfig, schemaName string, logger gormlogger.Interface) (*gorm.DB, error) {
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=pki port=%d search_path=%s sslmode=disable", cfg.Hostname, cfg.Username, cfg.Password, cfg.Port, schemaName)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger})
	if err != nil {
		return nil, err
	}

	if err := db.Exec(fmt.Sprintf("SET search_path TO %s", schemaName)).Error; err != nil {
		return nil, fmt.Errorf("set PostgreSQL search path: %w", err)
	}

	return db, nil
}
