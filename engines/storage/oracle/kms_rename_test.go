package oracle

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	coreconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/oracle/config"
)

// This test uses a disposable schema because it creates tables with the same
// names and constraints as the engine schema.
func TestOracleRenameKey(t *testing.T) {
	address := os.Getenv("LAMASSU_TEST_ORACLE_CONNECT_STRING")
	if address == "" {
		t.Skip("LAMASSU_TEST_ORACLE_CONNECT_STRING is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	pool, err := openDB(ctx, config.Config{ConnectString: address, Username: os.Getenv("LAMASSU_TEST_ORACLE_USERNAME"), Password: coreconfig.Password(os.Getenv("LAMASSU_TEST_ORACLE_PASSWORD")), MaxOpenConns: 4})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	for _, step := range []struct{ create, drop string }{
		{`CREATE TABLE lamassu_locks (lock_id VARCHAR2(64) PRIMARY KEY)`, `DROP TABLE lamassu_locks PURGE`},
		{`CREATE TABLE kms_keys (key_id VARCHAR2(128) NOT NULL, engine_id VARCHAR2(128) NOT NULL, aliases JSON, CONSTRAINT test_kms_pk PRIMARY KEY(key_id, engine_id))`, `DROP TABLE kms_keys PURGE`},
		{`CREATE TABLE certificates (serial_number VARCHAR2(128) PRIMARY KEY, key_id VARCHAR2(128), engine_id VARCHAR2(128), CONSTRAINT lamassu_cert_key_fk FOREIGN KEY(key_id, engine_id) REFERENCES kms_keys(key_id, engine_id) DEFERRABLE INITIALLY IMMEDIATE)`, `DROP TABLE certificates PURGE`},
	} {
		if _, err := pool.ExecContext(ctx, step.create); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if _, err := pool.ExecContext(context.Background(), step.drop); err != nil {
				t.Error(err)
			}
		})
	}
	for _, query := range []string{
		`INSERT INTO lamassu_locks VALUES ('kms_rename')`,
		`INSERT INTO kms_keys VALUES ('old', 'engine', '["previous"]')`,
		`INSERT INTO kms_keys VALUES ('old', 'other', '[]')`,
		`INSERT INTO certificates VALUES ('one', 'old', 'engine')`,
		`INSERT INTO certificates VALUES ('two', 'old', 'other')`,
	} {
		if _, err := pool.ExecContext(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
	db, err := openGORM(pool)
	if err != nil {
		t.Fatal(err)
	}
	callbackErr := errors.New("engine rename failed")
	if renamed, err := renameKey(ctx, db, "engine", "old", "new", func() error { return callbackErr }); renamed || !errors.Is(err, callbackErr) {
		t.Fatalf("callback failure: renamed=%v err=%v", renamed, err)
	}
	firstEntered, releaseFirst := make(chan struct{}), make(chan struct{})
	firstResult := make(chan error, 1)
	go func() {
		renamed, err := renameKey(ctx, db, "engine", "old", "new", func() error { close(firstEntered); <-releaseFirst; return nil })
		if err == nil && !renamed {
			err = errors.New("first rename did not occur")
		}
		firstResult <- err
	}()
	select {
	case <-firstEntered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	insertStarted := make(chan struct{})
	insertResult := make(chan error, 1)
	go func() {
		close(insertStarted)
		_, err := pool.ExecContext(ctx, `INSERT INTO certificates VALUES ('racing', 'old', 'engine')`)
		insertResult <- err
	}()
	<-insertStarted
	secondEntered := make(chan struct{}, 1)
	secondResult := make(chan error, 1)
	go func() {
		renamed, err := renameKey(ctx, db, "engine", "old", "other-new", func() error { secondEntered <- struct{}{}; return nil })
		if err == nil && renamed {
			err = errors.New("second rename unexpectedly succeeded")
		}
		secondResult <- err
	}()
	select {
	case <-secondEntered:
		t.Fatal("concurrent callback ran before the first transaction committed")
	case err := <-secondResult:
		t.Fatalf("concurrent rename returned before the first transaction committed: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	close(releaseFirst)
	if err := <-firstResult; err != nil {
		t.Fatal(err)
	}
	if err := <-secondResult; err != nil {
		t.Fatal(err)
	}
	insertErr := <-insertResult
	var keyID string
	if insertErr == nil {
		if err := pool.QueryRowContext(ctx, `SELECT key_id FROM certificates WHERE serial_number = 'racing'`).Scan(&keyID); err != nil || keyID != "new" {
			t.Fatalf("concurrent certificate was not moved with its key: key=%q error=%v", keyID, err)
		}
	}
	var staleReferences int
	if err := pool.QueryRowContext(ctx, `SELECT COUNT(*) FROM certificates WHERE key_id = 'old' AND engine_id = 'engine'`).Scan(&staleReferences); err != nil || staleReferences != 0 {
		t.Fatalf("stale certificate references after concurrent rename: count=%d error=%v", staleReferences, err)
	}
	select {
	case <-secondEntered:
		t.Fatal("callback ran for a missing key")
	default:
	}
	var aliasesJSON string
	if err := pool.QueryRowContext(ctx, `SELECT JSON_SERIALIZE(aliases RETURNING CLOB) FROM kms_keys WHERE key_id = 'new' AND engine_id = 'engine'`).Scan(&aliasesJSON); err != nil {
		t.Fatal(err)
	}
	var aliases []string
	if err := json.Unmarshal([]byte(aliasesJSON), &aliases); err != nil || !reflect.DeepEqual(aliases, []string{"previous", "old"}) {
		t.Fatalf("aliases %q: %v", aliasesJSON, err)
	}
	if err := pool.QueryRowContext(ctx, `SELECT key_id FROM certificates WHERE serial_number = 'one'`).Scan(&keyID); err != nil || keyID != "new" {
		t.Fatalf("renamed certificate: %q, %v", keyID, err)
	}
	if err := pool.QueryRowContext(ctx, `SELECT key_id FROM certificates WHERE serial_number = 'two'`).Scan(&keyID); err != nil || keyID != "old" {
		t.Fatalf("other engine certificate: %q, %v", keyID, err)
	}
	if _, err := pool.ExecContext(ctx, `DELETE FROM kms_keys WHERE key_id = 'new' AND engine_id = 'engine'`); err == nil {
		t.Fatal("the renamed key must remain protected by the certificate foreign key")
	}
	if _, err := pool.ExecContext(ctx, `INSERT INTO certificates VALUES ('missing', 'nonexistent', 'engine')`); err == nil {
		t.Fatal("a certificate must not reference a missing key")
	}
	if _, err := pool.ExecContext(ctx, `INSERT INTO kms_keys VALUES ('taken', 'engine', '[]')`); err != nil {
		t.Fatal(err)
	}
	called := false
	if renamed, err := renameKey(ctx, db, "engine", "new", "taken", func() error { called = true; return nil }); err == nil || renamed || !called {
		t.Fatalf("duplicate target: renamed=%v callback=%v error=%v", renamed, called, err)
	}
	if err := pool.QueryRowContext(ctx, `SELECT key_id FROM certificates WHERE serial_number = 'one'`).Scan(&keyID); err != nil || keyID != "new" {
		t.Fatalf("duplicate target must roll back references: %q, %v", keyID, err)
	}
}
