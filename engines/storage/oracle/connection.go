package oracle

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lamassuiot/lamassuiot/v4/engines/storage/oracle/config"
	oracledb "github.com/oracle/go-oracledb/v26/oracle"
)

// openDB opens and verifies a pool using separate credentials, so special
// characters in a password cannot change the connection descriptor.
func openDB(ctx context.Context, cfg config.Config) (*sql.DB, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	driverConfig := oracledb.NewOracleDriverConfig()
	driverConfig.ConnectDescriptor = cfg.ConnectString
	driverConfig.Credentials.User = cfg.Username
	driverConfig.Credentials.Password = string(cfg.Password)
	connector, err := oracledb.NewOracleConnector(driverConfig)
	if err != nil {
		return nil, fmt.Errorf("configure oracle connection: %w", err)
	}
	db := sql.OpenDB(connector)
	if cfg.MaxOpenConns > 0 {
		db.SetMaxOpenConns(cfg.MaxOpenConns)
	}
	if cfg.MaxIdleConns > 0 {
		db.SetMaxIdleConns(cfg.MaxIdleConns)
	}
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping oracle: %w", err)
	}
	return db, nil
}

// OpenDatabase opens and pings an Oracle connection pool for components that
// query an Oracle schema without constructing the full StorageEngine.
func OpenDatabase(ctx context.Context, cfg config.Config) (*sql.DB, error) {
	return openDB(ctx, cfg)
}
