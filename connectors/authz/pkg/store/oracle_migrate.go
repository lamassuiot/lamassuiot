package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/pressly/goose/v3"
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

// Insert records a migration as applied. upOracle has usually already
// recorded it as started (is_applied = 0) before running its DDL, so the row
// is updated when it exists.
func (oracleMigrationStore) Insert(ctx context.Context, db database.DBTxConn, req database.InsertRequest) error {
	_, err := db.ExecContext(ctx, `MERGE INTO AUTHZ_SCHEMA_MIGRATIONS t
		USING (SELECT :1 AS version_id FROM dual) s ON (t.version_id = s.version_id)
		WHEN MATCHED THEN UPDATE SET t.is_applied = 1
		WHEN NOT MATCHED THEN INSERT (version_id, is_applied) VALUES (s.version_id, 1)`, req.Version)
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

// ListMigrations lists the applied migrations. Goose treats every listed
// version as applied, so a migration recorded as started is left out.
func (oracleMigrationStore) ListMigrations(ctx context.Context, db database.DBTxConn) ([]*database.ListMigrationsResult, error) {
	rows, err := db.QueryContext(ctx,
		"SELECT version_id, is_applied FROM AUTHZ_SCHEMA_MIGRATIONS WHERE is_applied = 1 ORDER BY version_id DESC")
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

// ErrInterruptedMigration reports an Oracle Authz migration that started and
// did not finish. Oracle commits each DDL statement on its own, so part of its
// changes may be applied, and it must be recovered by hand before migrating.
var ErrInterruptedMigration = errors.New("Authz Oracle migration did not finish: manual recovery required")

// interruptedOracleMigration returns the version of a migration recorded as
// started but not applied, or 0 when there is none.
func interruptedOracleMigration(ctx context.Context, db *sql.DB) (int64, error) {
	var tables int
	if err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM USER_TABLES WHERE TABLE_NAME = :1", oracleVersionTable).Scan(&tables); err != nil {
		return 0, err
	}
	if tables == 0 {
		return 0, nil
	}
	var version sql.NullInt64
	if err := db.QueryRowContext(ctx,
		"SELECT MIN(version_id) FROM AUTHZ_SCHEMA_MIGRATIONS WHERE is_applied = 0").Scan(&version); err != nil {
		return 0, err
	}
	return version.Int64, nil
}

// upOracle applies pending migrations up to limit, one at a time. Before
// running a migration's DDL it records the version as started (is_applied = 0),
// and the goose store marks it applied once it succeeds. A failure therefore
// leaves the started row behind, and the next run refuses to continue instead
// of retrying DDL that Oracle may have partially committed.
func upOracle(ctx context.Context, db *sql.DB, provider *goose.Provider, limit int64) ([]*goose.MigrationResult, error) {
	if version, err := interruptedOracleMigration(ctx, db); err != nil {
		return nil, fmt.Errorf("check Authz Oracle migrations: %w", err)
	} else if version != 0 {
		return nil, fmt.Errorf("%w: version %d is recorded as started in %s; see docs/oracle-storage-engine.md", ErrInterruptedMigration, version, oracleVersionTable)
	}
	var results []*goose.MigrationResult
	for {
		current, err := provider.GetDBVersion(ctx)
		if err != nil {
			return results, fmt.Errorf("read Authz Oracle migration version: %w", err)
		}
		next := int64(0)
		for _, source := range provider.ListSources() {
			if source.Version > current {
				next = source.Version
				break
			}
		}
		if next == 0 || next > limit {
			return results, nil
		}
		if _, err := db.ExecContext(ctx,
			"INSERT INTO AUTHZ_SCHEMA_MIGRATIONS (version_id, is_applied) VALUES (:1, 0)", next); err != nil {
			return results, fmt.Errorf("record Authz Oracle migration %d as started: %w", next, err)
		}
		result, err := provider.UpByOne(ctx)
		if result != nil {
			results = append(results, result)
		}
		if err != nil {
			return results, fmt.Errorf("%w: version %d failed and may be partially applied: %w", ErrInterruptedMigration, next, err)
		}
	}
}
