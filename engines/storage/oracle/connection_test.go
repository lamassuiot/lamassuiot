package oracle

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	coreconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/oracle/config"
)

// Set these variables to run against a disposable Oracle schema.
func TestOracleConnection(t *testing.T) {
	connectString := os.Getenv("LAMASSU_TEST_ORACLE_CONNECT_STRING")
	if connectString == "" {
		t.Skip("LAMASSU_TEST_ORACLE_CONNECT_STRING is not set")
	}
	cfg := config.Config{
		ConnectString: connectString,
		Username:      os.Getenv("LAMASSU_TEST_ORACLE_USERNAME"),
		Password:      coreconfig.Password(os.Getenv("LAMASSU_TEST_ORACLE_PASSWORD")),
		MaxOpenConns:  2,
		MaxIdleConns:  1,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := openDB(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var value int
	if err := db.QueryRowContext(ctx, "SELECT 1 FROM DUAL").Scan(&value); err != nil || value != 1 {
		t.Fatalf("query: value=%d error=%v", value, err)
	}
	if got := db.Stats().MaxOpenConnections; got != 2 {
		t.Fatalf("max connections = %d; want 2", got)
	}

	cancelled, cancelImmediately := context.WithCancel(context.Background())
	cancelImmediately()
	if _, err := openDB(cancelled, cfg); err == nil {
		t.Fatal("expected connection to fail with a cancelled context")
	}

	singleConnCfg := cfg
	singleConnCfg.MaxOpenConns = 1
	singleConnCfg.MaxIdleConns = 1
	singleConnDB, err := openDB(ctx, singleConnCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer singleConnDB.Close()
	tx, err := singleConnDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	waitCtx, cancelWait := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancelWait()
	err = singleConnDB.QueryRowContext(waitCtx, "SELECT 1 FROM DUAL").Scan(&value)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("pool-exhausted query error = %v; want context deadline exceeded", err)
	}
	if got := singleConnDB.Stats().WaitCount; got == 0 {
		t.Fatal("pool exhaustion did not record a connection wait")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := singleConnDB.QueryRowContext(ctx, "SELECT 1 FROM DUAL").Scan(&value); err != nil || value != 1 {
		t.Fatalf("query after releasing the pooled connection: value=%d error=%v", value, err)
	}
}
