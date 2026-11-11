package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/pressly/goose/v3/database"
)

const oracleVersionTable = "AUTHZ_SCHEMA_MIGRATIONS"

type oracleMigrationStore struct{}

func newOracleMigrationStore() database.Store {
	return oracleMigrationStore{}
}

func (oracleMigrationStore) Tablename() string { return oracleVersionTable }

func (s oracleMigrationStore) TableExists(ctx context.Context, db database.DBTxConn) (bool, error) {
	var count int
	err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM USER_TABLES WHERE TABLE_NAME = :1", oracleVersionTable).Scan(&count)
	return count > 0, err
}

func (s oracleMigrationStore) CreateVersionTable(ctx context.Context, db database.DBTxConn) error {
	if _, err := db.ExecContext(ctx, `CREATE TABLE AUTHZ_SCHEMA_MIGRATIONS (
		version_id NUMBER(19) NOT NULL PRIMARY KEY,
		is_applied NUMBER(1) NOT NULL
	)`); err != nil {
		return fmt.Errorf("create Oracle Authz migration table: %w", err)
	}
	return nil
}

func (oracleMigrationStore) Insert(ctx context.Context, db database.DBTxConn, req database.InsertRequest) error {
	_, err := db.ExecContext(ctx,
		"INSERT INTO AUTHZ_SCHEMA_MIGRATIONS (version_id, is_applied) VALUES (:1, 1)", req.Version)
	return err
}

func (oracleMigrationStore) Delete(ctx context.Context, db database.DBTxConn, version int64) error {
	_, err := db.ExecContext(ctx,
		"DELETE FROM AUTHZ_SCHEMA_MIGRATIONS WHERE version_id = :1", version)
	return err
}

func (oracleMigrationStore) GetMigration(ctx context.Context, db database.DBTxConn, version int64) (*database.GetMigrationResult, error) {
	var applied int
	err := db.QueryRowContext(ctx,
		"SELECT is_applied FROM AUTHZ_SCHEMA_MIGRATIONS WHERE version_id = :1", version).Scan(&applied)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, database.ErrVersionNotFound
	}
	if err != nil {
		return nil, err
	}
	return &database.GetMigrationResult{Timestamp: time.Time{}, IsApplied: applied != 0}, nil
}

func (oracleMigrationStore) GetLatestVersion(ctx context.Context, db database.DBTxConn) (int64, error) {
	var version sql.NullInt64
	err := db.QueryRowContext(ctx,
		"SELECT MAX(version_id) FROM AUTHZ_SCHEMA_MIGRATIONS WHERE is_applied = 1").Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, database.ErrVersionNotFound
	}
	if err != nil {
		return 0, err
	}
	if !version.Valid {
		return 0, database.ErrVersionNotFound
	}
	return version.Int64, nil
}

func (oracleMigrationStore) ListMigrations(ctx context.Context, db database.DBTxConn) ([]*database.ListMigrationsResult, error) {
	rows, err := db.QueryContext(ctx,
		"SELECT version_id, is_applied FROM AUTHZ_SCHEMA_MIGRATIONS ORDER BY version_id DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*database.ListMigrationsResult
	for rows.Next() {
		var version int64
		var applied int
		if err := rows.Scan(&version, &applied); err != nil {
			return nil, err
		}
		result = append(result, &database.ListMigrationsResult{Version: version, IsApplied: applied != 0})
	}
	return result, rows.Err()
}

var _ database.StoreExtender = oracleMigrationStore{}
