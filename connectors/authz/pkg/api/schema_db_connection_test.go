package api

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/sirupsen/logrus"
)

func TestCreateSchemaDBConnectionValidatesOracleConfiguration(t *testing.T) {
	_, err := CreateSchemaDBConnection(logrus.NewEntry(logrus.New()), cconfig.PluggableStorageEngine{
		Provider: cconfig.StorageProvider("oracle"),
		Config:   map[string]any{},
	})
	if err == nil || !strings.Contains(err.Error(), "oracle connect_string is required") {
		t.Fatalf("Oracle schema config error = %v, want missing connect_string", err)
	}
}

func TestCreateSchemaDBConnectionRejectsUnknownProvider(t *testing.T) {
	_, err := CreateSchemaDBConnection(logrus.NewEntry(logrus.New()), cconfig.PluggableStorageEngine{
		Provider: cconfig.StorageProvider("mysql"),
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported Authz schema database provider") {
		t.Fatalf("unknown provider error = %v", err)
	}
}

func TestCreateSchemaDBConnectionDefaultsToPostgres(t *testing.T) {
	_, err := CreateSchemaDBConnection(logrus.NewEntry(logrus.New()), cconfig.PluggableStorageEngine{
		Config: map[string]any{},
	})
	if err == nil || !strings.Contains(err.Error(), "postgres config is missing required field 'database'") {
		t.Fatalf("default provider error = %v, want Postgres config validation", err)
	}
}

func TestCreateSchemaDBConnectionOracle(t *testing.T) {
	connectString := os.Getenv("LAMASSU_TEST_ORACLE_CONNECT_STRING")
	if connectString == "" {
		t.Skip("LAMASSU_TEST_ORACLE_CONNECT_STRING is not set")
	}
	db, err := CreateSchemaDBConnection(logrus.NewEntry(logrus.New()), cconfig.PluggableStorageEngine{
		Provider: cconfig.StorageProvider("oracle"),
		Config: map[string]any{
			"connect_string":    connectString,
			"username":          os.Getenv("LAMASSU_TEST_ORACLE_USERNAME"),
			"password":          os.Getenv("LAMASSU_TEST_ORACLE_PASSWORD"),
			"max_open_conns":    2,
			"conn_max_lifetime": "1m",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sqlDB.PingContext(ctx); err != nil {
		t.Fatalf("Authz Oracle schema connection ping: %v", err)
	}
}
