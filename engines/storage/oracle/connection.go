package oracle

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/engines/storage/oracle/config"
	oracledb "github.com/oracle/go-oracledb/v26/oracle"
)

// openDB opens and verifies a pool using separate credentials, so special
// characters in a password cannot change the connection descriptor.
func openDB(ctx context.Context, cfg config.Config) (*sql.DB, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return openDBWithOptions(ctx, ConnectionOptions{
		ConnectString:   cfg.ConnectString,
		Username:        cfg.Username,
		Password:        string(cfg.Password),
		MaxOpenConns:    cfg.MaxOpenConns,
		MaxIdleConns:    cfg.MaxIdleConns,
		ConnMaxLifetime: cfg.ConnMaxLifetime,
	})
}

// ConnectionOptions describes the connection pool needed by consumers that
// own their configuration model and use the Oracle storage engine for access.
type ConnectionOptions struct {
	ConnectString   string
	Username        string
	Password        string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

func openDBWithOptions(ctx context.Context, cfg ConnectionOptions) (*sql.DB, error) {
	if strings.TrimSpace(cfg.ConnectString) == "" {
		return nil, fmt.Errorf("oracle connect_string is required")
	}
	if strings.TrimSpace(cfg.Username) == "" {
		return nil, fmt.Errorf("oracle username is required")
	}
	if cfg.MaxOpenConns < 0 || cfg.MaxIdleConns < 0 || cfg.ConnMaxLifetime < 0 {
		return nil, fmt.Errorf("oracle pool settings cannot be negative")
	}
	if cfg.MaxOpenConns > 0 && cfg.MaxIdleConns > cfg.MaxOpenConns {
		return nil, fmt.Errorf("oracle max_idle_conns cannot exceed max_open_conns")
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

// OpenDatabaseWithOptions opens an Oracle connection pool from connection
// options, allowing callers to keep ownership of their configuration types.
func OpenDatabaseWithOptions(ctx context.Context, cfg ConnectionOptions) (*sql.DB, error) {
	return openDBWithOptions(ctx, cfg)
}
