package oracle

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	coreconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/oracle/config"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/oracle/migrations"
)

func TestOracleMigrationRecovery(t *testing.T) {
	address := os.Getenv("LAMASSU_TEST_ORACLE_CONNECT_STRING")
	if address == "" {
		t.Skip("LAMASSU_TEST_ORACLE_CONNECT_STRING is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	pool, err := openDB(ctx, config.Config{ConnectString: address, Username: os.Getenv("LAMASSU_TEST_ORACLE_USERNAME"), Password: coreconfig.Password(os.Getenv("LAMASSU_TEST_ORACLE_PASSWORD")), MaxOpenConns: 6})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	defer func() {
		for _, table := range []string{"lamassu_migration_probe2", "lamassu_migration_probe", "lamassu_schema_migrations", "lamassu_migration_lock"} {
			// Some objects intentionally do not exist when the test fails early.
			_, _ = pool.ExecContext(context.Background(), "DROP TABLE "+table+" PURGE")
		}
	}()
	plan := []migrations.Migration{{Version: 1, Name: "test", Statements: []string{`CREATE TABLE lamassu_migration_probe (id NUMBER PRIMARY KEY)`}}}
	if err := migrations.Check(ctx, pool, plan); err == nil {
		t.Fatal("uninstalled schema passed the version check")
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- migrations.Apply(ctx, pool, plan) }()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := migrations.Check(ctx, pool, plan); err != nil {
		t.Fatalf("installed schema check: %v", err)
	}
	future := append(append([]migrations.Migration{}, plan...), migrations.Migration{Version: 2, Name: "next", Statements: []string{`CREATE TABLE unused_test_table (id NUMBER)`}})
	if err := migrations.Check(ctx, pool, future); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("missing migration check: %v", err)
	}
	var count int
	if err := pool.QueryRowContext(ctx, `SELECT COUNT(*) FROM lamassu_schema_migrations WHERE version = 1 AND state = 'APPLIED'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("applied count=%d error=%v", count, err)
	}
	changed := []migrations.Migration{{Version: 1, Name: "test", Statements: []string{`CREATE TABLE lamassu_migration_probe (id NUMBER)`}}}
	if err := migrations.Apply(ctx, pool, changed); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("changed migration: %v", err)
	}
	broken := append(plan, migrations.Migration{Version: 2, Name: "broken", Statements: []string{`CREATE TABLE lamassu_migration_probe2 (id NUMBER)`, `INVALID SQL`}})
	if err := migrations.Apply(ctx, pool, broken); err == nil || !strings.Contains(err.Error(), "manual recovery") {
		t.Fatalf("expected failed migration: %v", err)
	}
	if err := migrations.Apply(ctx, pool, broken); err == nil || !strings.Contains(err.Error(), "STARTED") {
		t.Fatalf("expected dirty migration: %v", err)
	}
	if err := migrations.Check(ctx, pool, broken); err == nil || !strings.Contains(err.Error(), "STARTED") {
		t.Fatalf("dirty schema check: %v", err)
	}
	if err := pool.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_tables WHERE table_name = 'LAMASSU_MIGRATION_PROBE2'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("committed DDL count=%d error=%v", count, err)
	}
}
