package transport

import (
	"context"

	postgresconfig "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/config"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// Open creates a GORM connection using the configured PostgreSQL transport.
func Open(ctx context.Context, cfg postgresconfig.PostgresPSEConfig, schemaName string, logger gormlogger.Interface) (*gorm.DB, error) {
	if cfg.UsesRDSDataAPI() {
		return openRDSDataAPI(ctx, cfg, schemaName, logger)
	}
	return openDirect(cfg, schemaName, logger)
}
