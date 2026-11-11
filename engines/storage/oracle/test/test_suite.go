package test

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/oracle"
	oracleconfig "github.com/lamassuiot/lamassuiot/v4/engines/storage/oracle/config"
	"github.com/lamassuiot/lamassuiot/v4/shared/subsystems/pkg/test/dockerrunner"
	"github.com/moby/moby/api/types/network"
	"github.com/ory/dockertest/v4"
)

const (
	oracleImageTag = "23.26.3-slim-faststart"
	oracleUser     = "lamassu"
	oraclePassword = "LamassuTest123"
)

type OracleSuite struct {
	DB            *sql.DB
	cleanupDocker func() error
}

// BeforeSuite starts a disposable Oracle Free database and waits for the
// application user to accept connections.
func BeforeSuite(exposeAsStandardPort bool) (oracleconfig.Config, *OracleSuite, error) {
	options := []dockertest.RunOption{
		dockertest.WithTag(oracleImageTag),
		dockertest.WithEnv([]string{
			"ORACLE_PASSWORD=" + oraclePassword,
			"APP_USER=" + oracleUser,
			"APP_USER_PASSWORD=" + oraclePassword,
		}),
		dockertest.WithLabels(map[string]string{"group": "lamassuiot-tests", "engine": "oracle"}),
	}
	hostPort := ""
	if exposeAsStandardPort {
		hostPort = "1521"
	}
	options = append(options, dockertest.WithPortBindings(network.PortMap{
		network.MustParsePort("1521/tcp"): []network.PortBinding{{
			HostIP: netip.MustParseAddr("0.0.0.0"), HostPort: hostPort,
		}},
	}))

	cleanup, container, dockerHost, err := dockerrunner.RunDocker("gvenzl/oracle-free", options...)
	if err != nil {
		return oracleconfig.Config{}, nil, err
	}
	connectString := fmt.Sprintf("localhost:%s/FREEPDB1", container.GetPort("1521/tcp"))
	if strings.Contains(connectString, "localhost:/") {
		_ = cleanup()
		return oracleconfig.Config{}, nil, fmt.Errorf("Oracle test container did not publish port 1521")
	}
	cfg := oracleconfig.Config{
		ConnectString: connectString,
		Username:      oracleUser,
		Password:      config.Password(oraclePassword),
		MaxOpenConns:  8,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	var db *sql.DB
	err = dockerHost.Retry(ctx, 3*time.Minute, func() error {
		var openErr error
		db, openErr = oracle.OpenDatabase(ctx, cfg)
		return openErr
	})
	if err != nil {
		_ = cleanup()
		return oracleconfig.Config{}, nil, fmt.Errorf("wait for Oracle test database: %w", err)
	}
	return cfg, &OracleSuite{DB: db, cleanupDocker: cleanup}, nil
}

// BeforeEach deletes application rows while preserving migration history.
func (suite *OracleSuite) BeforeEach() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return clearApplicationRows(ctx, suite.DB)
}

func (suite *OracleSuite) AfterSuite() {
	if suite.DB != nil {
		_ = suite.DB.Close()
	}
	if suite.cleanupDocker != nil {
		_ = suite.cleanupDocker()
	}
}

func clearApplicationRows(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `SELECT table_name FROM user_tables`)
	if err != nil {
		return fmt.Errorf("list Oracle test tables: %w", err)
	}
	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan Oracle test table: %w", err)
		}
		tables = append(tables, table)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("read Oracle test tables: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close Oracle test table list: %w", err)
	}

	order, err := childFirstTableOrder(ctx, db, tables)
	if err != nil {
		return err
	}
	for _, table := range order {
		if table == "LAMASSU_SCHEMA_MIGRATIONS" || table == "LAMASSU_MIGRATION_LOCK" || table == "LAMASSU_LOCKS" {
			continue
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM "`+strings.ReplaceAll(table, `"`, `""`)+`"`); err != nil {
			return fmt.Errorf("clear Oracle test table %s: %w", table, err)
		}
	}
	return nil
}

func childFirstTableOrder(ctx context.Context, db *sql.DB, tables []string) ([]string, error) {
	tableSet := make(map[string]struct{}, len(tables))
	childrenByParent := make(map[string][]string, len(tables))
	indegree := make(map[string]int, len(tables))
	for _, table := range tables {
		tableSet[table] = struct{}{}
		indegree[table] = 0
	}
	rows, err := db.QueryContext(ctx, `
		SELECT child.table_name, parent.table_name
		FROM user_constraints child
		JOIN user_constraints parent ON parent.constraint_name = child.r_constraint_name
		WHERE child.constraint_type = 'R' AND child.status = 'ENABLED'
	`)
	if err != nil {
		return nil, fmt.Errorf("read Oracle test foreign keys: %w", err)
	}
	for rows.Next() {
		var child, parent string
		if err := rows.Scan(&child, &parent); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("scan Oracle test foreign key: %w", err)
		}
		if child == parent {
			continue
		}
		if _, ok := tableSet[child]; !ok {
			continue
		}
		if _, ok := tableSet[parent]; !ok {
			continue
		}
		childrenByParent[child] = append(childrenByParent[child], parent)
		indegree[parent]++
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("read Oracle test foreign keys: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close Oracle test foreign keys: %w", err)
	}

	var ready []string
	for table, count := range indegree {
		if count == 0 {
			ready = append(ready, table)
		}
	}
	sort.Strings(ready)
	order := make([]string, 0, len(tables))
	for len(ready) > 0 {
		table := ready[0]
		ready = ready[1:]
		order = append(order, table)
		for _, parent := range childrenByParent[table] {
			indegree[parent]--
			if indegree[parent] == 0 {
				ready = append(ready, parent)
				sort.Strings(ready)
			}
		}
	}
	if len(order) != len(tables) {
		return nil, fmt.Errorf("Oracle test schema contains a cyclic foreign-key dependency")
	}
	return order, nil
}
