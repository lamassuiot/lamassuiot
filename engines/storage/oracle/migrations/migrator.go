// Package migrations applies versioned Oracle DDL with a durable dirty marker.
package migrations

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	oracleerrors "github.com/oracle/go-oracledb/v26/oracle/errors"
)

// Migration consists of ordered, individually executed SQL statements. Oracle
// DDL commits implicitly, so a failed migration is never retried automatically.
type Migration struct {
	Version    int64
	Name       string
	Statements []string
}

func (m Migration) checksum() string {
	h := sha256.New()
	// Length prefixes avoid ambiguity between different statement sequences.
	for _, value := range append([]string{strconv.FormatInt(m.Version, 10), m.Name}, m.Statements...) {
		fmt.Fprintf(h, "%d:", len(value))
		h.Write([]byte(value))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func hasOracleCode(err error, code string) bool {
	var sqlErr oracleerrors.SQLError
	return errors.As(err, &sqlErr) && sqlErr.ErrorCode() == code
}

func bootstrap(ctx context.Context, db *sql.DB) error {
	for _, stmt := range []string{
		`CREATE TABLE lamassu_migration_lock (id NUMBER(1) PRIMARY KEY CHECK (id = 1))`,
		`CREATE TABLE lamassu_schema_migrations (version NUMBER(19) PRIMARY KEY, name VARCHAR2(200) NOT NULL, checksum VARCHAR2(64) NOT NULL, state VARCHAR2(16) NOT NULL, updated_at TIMESTAMP WITH TIME ZONE NOT NULL)`,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil && !hasOracleCode(err, "ORA-00955") {
			return fmt.Errorf("bootstrap migration metadata: %w", err)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO lamassu_migration_lock (id) VALUES (1)`); err != nil && !hasOracleCode(err, "ORA-00001") {
		return fmt.Errorf("bootstrap migration lock: %w", err)
	}
	return nil
}

func validatePlan(migrations []Migration) error {
	if len(migrations) == 0 {
		return errors.New("oracle migration plan is empty")
	}
	for i, m := range migrations {
		if m.Version <= 0 || m.Name == "" || len(m.Statements) == 0 || (i > 0 && m.Version <= migrations[i-1].Version) {
			return fmt.Errorf("invalid oracle migration at index %d", i)
		}
		for _, stmt := range m.Statements {
			if stmt == "" {
				return fmt.Errorf("empty statement in migration %d", m.Version)
			}
		}
	}
	return nil
}

// Apply serializes migrators using a separate transaction whose row lock
// survives commits caused by DDL on the execution connection. The pool must
// allow at least two connections. A dirty migration requires operator recovery.
func Apply(ctx context.Context, db *sql.DB, migrations []Migration) error {
	if err := validatePlan(migrations); err != nil {
		return err
	}
	if max := db.Stats().MaxOpenConnections; max == 1 {
		return errors.New("oracle migrations require at least two pool connections")
	}
	if err := bootstrap(ctx, db); err != nil {
		return err
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	lock, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer lock.Rollback()
	var id int
	if err := lock.QueryRowContext(ctx, `SELECT id FROM lamassu_migration_lock WHERE id = 1 FOR UPDATE`).Scan(&id); err != nil {
		return fmt.Errorf("acquire oracle migration lock: %w", err)
	}

	applied, err := appliedCount(ctx, db, migrations)
	if err != nil {
		return err
	}

	for _, m := range migrations[applied:] {
		_, err := db.ExecContext(ctx, `INSERT INTO lamassu_schema_migrations (version, name, checksum, state, updated_at) VALUES (:1, :2, :3, 'STARTED', SYSTIMESTAMP)`, m.Version, m.Name, m.checksum())
		if err != nil {
			return fmt.Errorf("record oracle migration %d: %w", m.Version, err)
		}
		for i, statement := range m.Statements {
			if _, err := db.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("oracle migration %d statement %d failed; manual recovery required: %w", m.Version, i+1, err)
			}
		}
		result, err := db.ExecContext(ctx, `UPDATE lamassu_schema_migrations SET state = 'APPLIED', updated_at = SYSTIMESTAMP WHERE version = :1 AND state = 'STARTED'`, m.Version)
		if err != nil {
			return fmt.Errorf("complete oracle migration %d: %w", m.Version, err)
		}
		if n, err := result.RowsAffected(); err != nil || n != 1 {
			return fmt.Errorf("complete oracle migration %d: unexpected affected rows %d: %v", m.Version, n, err)
		}
	}
	return nil
}

// Check verifies an existing installation without creating or changing schema.
// It rejects incomplete, changed, dirty and newer migration histories.
func Check(ctx context.Context, db *sql.DB, migrations []Migration) error {
	if err := validatePlan(migrations); err != nil {
		return err
	}
	applied, err := appliedCount(ctx, db, migrations)
	if err != nil {
		return err
	}
	if applied != len(migrations) {
		return fmt.Errorf("oracle schema is incomplete: %d of %d migrations applied", applied, len(migrations))
	}
	return nil
}

func appliedCount(ctx context.Context, db *sql.DB, migrations []Migration) (int, error) {
	rows, err := db.QueryContext(ctx, `SELECT version, name, checksum, state FROM lamassu_schema_migrations ORDER BY version`)
	if err != nil {
		return 0, err
	}
	applied := 0
	for rows.Next() {
		var version int64
		var name, checksum, state string
		if err := rows.Scan(&version, &name, &checksum, &state); err != nil {
			rows.Close()
			return 0, err
		}
		if applied >= len(migrations) || migrations[applied].Version != version || migrations[applied].Name != name || migrations[applied].checksum() != checksum {
			rows.Close()
			return 0, fmt.Errorf("unknown or changed oracle migration %d", version)
		}
		if state != "APPLIED" {
			rows.Close()
			return 0, fmt.Errorf("oracle migration %d is %s: manual recovery required", version, state)
		}
		applied++
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	return applied, nil
}
