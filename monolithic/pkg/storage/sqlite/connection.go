package sqlite

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// sqliteConnWrapper wraps the SQL connection to replace ILIKE with LIKE
type sqliteConnWrapper struct {
	gorm.ConnPool
}

func (c *sqliteConnWrapper) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	query = strings.ReplaceAll(query, " ILIKE ", " LIKE ")
	return c.ConnPool.ExecContext(ctx, query, args...)
}

func (c *sqliteConnWrapper) QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	query = strings.ReplaceAll(query, " ILIKE ", " LIKE ")
	return c.ConnPool.QueryContext(ctx, query, args...)
}

func (c *sqliteConnWrapper) QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row {
	query = strings.ReplaceAll(query, " ILIKE ", " LIKE ")
	return c.ConnPool.QueryRowContext(ctx, query, args...)
}

func (c *sqliteConnWrapper) PrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	query = strings.ReplaceAll(query, " ILIKE ", " LIKE ")
	return c.ConnPool.PrepareContext(ctx, query)
}

func CreateSQLiteDBConnection(log *logrus.Entry, dbPath string) (*gorm.DB, error) {
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}

	// Wrap ConnPool to replace ILIKE with LIKE
	db.ConnPool = &sqliteConnWrapper{ConnPool: db.ConnPool}

	// Get underlying SQL DB for connection pool configuration
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	// Configure connection pool for concurrency protection
	// SQLite performs best with a single writer, so limit max open connections
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(time.Hour)

	// Enable WAL mode for better concurrent read/write performance
	if err := db.Exec("PRAGMA journal_mode = WAL").Error; err != nil {
		return nil, err
	}

	// Enable Foreign Keys
	if err := db.Exec("PRAGMA foreign_keys = ON").Error; err != nil {
		return nil, err
	}

	// Set busy timeout to wait up to 5 seconds for locks
	if err := db.Exec("PRAGMA busy_timeout = 5000").Error; err != nil {
		return nil, err
	}

	// Set synchronous mode to NORMAL for better performance while maintaining safety
	if err := db.Exec("PRAGMA synchronous = NORMAL").Error; err != nil {
		return nil, err
	}

	// Disable case-sensitive LIKE to match PostgreSQL ILIKE behavior
	if err := db.Exec("PRAGMA case_sensitive_like = OFF").Error; err != nil {
		return nil, err
	}

	return db, nil
}
