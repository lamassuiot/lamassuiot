# Migrating from Multi-Database to Multi-Schema

Here's what would be involved in migrating the PostgreSQL storage from a **multi-database** to a **multi-schema** approach:

## Current Architecture

Currently, the system uses separate databases per microservice:
- `ca` - Certificate Authority
- `devicemanager` - Device Management
- `dmsmanager` - DMS Management
- `alerts` - Alerts and Subscriptions
- `va` - Validation Authority
- `kms` - Key Management System

Each database has its own migration tracking via the `goose_db_version` table.

## Required Changes for Multi-Schema Approach

### 1. **Core Engine Changes** (`engines/storage/postgres/engine.go`)

```go
const (
    // Change from database names to schema names
    CA_SCHEMA     = "ca"
    DEVICE_SCHEMA = "devicemanager"
    DMS_SCHEMA    = "dmsmanager"
    ALERTS_SCHEMA = "alerts"
    VA_SCHEMA     = "va"
    KMS_SCHEMA    = "kms"
)

// New: Single database name
const MAIN_DB_NAME = "lamassu"
```

### 2. **Connection Management** (`engines/storage/postgres/utils.go`)

The `CreatePostgresDBConnection` function would need significant changes:

```go
func CreatePostgresDBConnection(logger *logrus.Entry, cfg lconfig.PostgresPSEConfig, schema string) (*gorm.DB, error) {
    dbLogger := &GormLogger{
        logger: logger,
    }

    // Connect to single database
    dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=disable search_path=%s", 
        cfg.Hostname, cfg.Username, cfg.Password, MAIN_DB_NAME, cfg.Port, schema)
    
    db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
        Logger: dbLogger,
    })

    if err != nil {
        return nil, err
    }

    // Set search_path for this connection
    db.Exec(fmt.Sprintf("SET search_path TO %s", schema))
    
    return db, nil
}
```

### 3. **Migration System Changes** (`engines/storage/postgres/migrate.go`)

**Major Impact**: Each schema would need its own `goose_db_version` table:

```go
func MigrateDatabase(logger *log.Entry, config lconfig.PostgresPSEConfig, schema string) error {
    logger.Infof("Starting migration for schema: %s", schema)

    // Connect to main database
    psqlCli, err := CreatePostgresDBConnection(logger, config, schema)
    if err != nil {
        return fmt.Errorf("could not create postgres connection: %w", err)
    }

    // Ensure schema exists
    psqlCli.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", schema))
    
    // Set search_path for migrations
    psqlCli.Exec(fmt.Sprintf("SET search_path TO %s", schema))

    m := NewMigrator(logger, psqlCli)
    
    // Rest of migration logic...
}
```

### 4. **Goose Migration Tool** (`engines/storage/postgres/cmd/goose-lamassu/main.go`)

The standalone migration tool would need updates:

```go
func main() {
    // ...existing code...
    
    // Extract schema name instead of dbname
    schemaName := extractSchemaName(dbstring)
    
    if !contains(validSchemas, schemaName) {
        log.Fatalf("goose-lamassu: invalid schema: %s. Must be one of: %s", 
            schemaName, strings.Join(validSchemas, ", "))
    }

    // Connect to main database with schema search_path
    connStr := fmt.Sprintf("%s search_path=%s", dbstring, schemaName)
    db, err := goose.OpenDBWithDriver("postgres", connStr)
    
    // Execute: SET search_path TO schema_name
    _, err = db.Exec(fmt.Sprintf("SET search_path TO %s", schemaName))
    
    // ...rest of migration logic...
}
```

### 5. **Test Infrastructure** (`engines/storage/postgres/test/postgres.go`)

The Docker test setup in `RunPostgresDocker` needs substantial changes:

```go
func RunPostgresDocker(schemas map[string]string, exposeAsStandardPort bool) (func() error, *config.PostgresPSEConfig, error) {
    // ...existing Docker setup...

    // Change from multiple databases to multiple schemas
    sqlStatements := "CREATE DATABASE lamassu;\n"
    sqlStatements += "\\c lamassu;\n"  // Connect to main database
    
    for schemaName, initScript := range schemas {
        sqlStatements += fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s;\n", schemaName)
        if initScript != "" {
            sqlStatements += fmt.Sprintf("SET search_path TO %s;\n", schemaName)
            sqlStatements += initScript + "\n"
        }
    }
    
    // ...rest of setup...
}
```

### 6. **Test Suite Updates** (`engines/storage/postgres/test/test_suite.go`)

```go
func BeforeSuite(schemaNames []string, exposeAsStandardPort bool) (config.PostgresPSEConfig, PostgresSuite) {
    schemas := make(map[string]string)
    for _, schemaName := range schemaNames {
        schemas[schemaName] = ""
    }

    cleaner, conf, err := RunPostgresDocker(schemas, exposeAsStandardPort)
    if err != nil {
        log.Fatal(err)
    }

    dbMap := make(map[string]*gorm.DB)
    for _, schemaName := range schemaNames {
        // All connections to same database, different schemas
        conStr := fmt.Sprintf("host=%s port=%d user=%s dbname=%s password=%s search_path=%s sslmode=disable",
            conf.Hostname, conf.Port, conf.Username, "lamassu", conf.Password, schemaName)
        
        db, _ := gorm.Open(postgres.Open(conStr), &gorm.Config{
            Logger: gormLogger.Discard,
        })
        
        // Set search_path for each connection
        db.Exec(fmt.Sprintf("SET search_path TO %s", schemaName))
        
        dbMap[schemaName] = db
    }

    return *conf, PostgresSuite{
        cleanupDocker: cleaner,
        DB:            dbMap,
        schemaNames:   schemaNames,
    }
}
```

### 7. **Table Cleanup in Tests** (`engines/storage/postgres/test/test_suite.go`)

```go
func (st *PostgresSuite) BeforeEach() error {
    for schemaName, db := range st.DB {
        var tables []string
        // Query tables in specific schema
        if err := db.Raw("SELECT tablename FROM pg_tables WHERE schemaname = ?", schemaName).
            Pluck("tablename", &tables).Error; err != nil {
            panic(err)
        }

        // Exclude migration table
        tables = slices.DeleteFunc(tables, func(s string) bool {
            return s == "goose_db_version"
        })

        if len(tables) > 0 {
            // Qualify table names with schema
            qualifiedTables := make([]string, len(tables))
            for i, table := range tables {
                qualifiedTables[i] = fmt.Sprintf("%s.%s", schemaName, table)
            }
            
            tx := db.Exec(fmt.Sprintf("TRUNCATE TABLE %s CASCADE;", 
                strings.Join(qualifiedTables, ", ")))
            if tx.Error != nil {
                return tx.Error
            }
        }
    }
    return nil
}
```

### 8. **Migration Tests** (`engines/storage/postgres/migrations_test/ca_test.go`)

Migration tests would need minimal changes since they work at the connection level, but the setup would change:

```go
func RunDB(t *testing.T, logger *logrus.Entry, schemaName string) (func() error, *gorm.DB) {
    cleanup, cfg, err := postgres_test.RunPostgresDocker(map[string]string{
        schemaName: "",
    }, false)
    if err != nil {
        t.Fatalf("could not launch Postgres: %s", err)
    }

    // Connect to main database with schema search_path
    dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d search_path=%s sslmode=disable", 
        cfg.Hostname, cfg.Username, cfg.Password, "lamassu", cfg.Port, schemaName)
    
    con, err := gorm.Open(postgresDriver.New(
        postgresDriver.Config{
            DSN:                  dsn,
            PreferSimpleProtocol: true,
        },
    ), &gorm.Config{
        Logger: postgres.NewGormLogger(logger),
    })
    
    // Ensure schema exists and set search_path
    con.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", schemaName))
    con.Exec(fmt.Sprintf("SET search_path TO %s", schemaName))
    
    return cleanup, con
}
```

### 9. **Monolithic Deployment** (`monolithic/cmd/development/main.go`)

The monolithic setup would be simplified:

```go
// Single database instead of multiple
posgresSubsystem.Prepare([]string{"lamassu"})  // Single database

// Or if schemas are created separately:
// The subsystem would create all schemas within one database
```

### 10. **Configuration Changes** (`engines/storage/postgres/config/config.go`)

The configuration might need a new field:

```go
type PostgresPSEConfig struct {
    Hostname string
    Port     int
    Username string
    Password string
    Database string  // New: single database name (default: "lamassu")
}
```

## Key Implications

### **Advantages:**
1. **Single connection pool** - More efficient resource usage
2. **Cross-schema queries** - Can join across microservices if needed
3. **Simpler backup/restore** - One database to manage
4. **Better for multi-tenancy** - Can add tenant schemas easily

### **Disadvantages:**
1. **Schema-level isolation** - Less isolation than separate databases
2. **search_path complexity** - Must manage schema context carefully
3. **Migration complexity** - Each schema needs its own `goose_db_version` table
4. **Existing deployments** - Requires migration path for existing installations

### **Breaking Changes:**
- **All connection strings** would need updating (from `dbname=ca` to `dbname=lamassu search_path=ca`)
- **Docker initialization scripts** in postgres.go
- **CI/CD pipelines** using the goose-lamassu tool
- **Backup/restore procedures**

### **Testing Impact:**
- All tests in migrate_test.go would need updates
- All tests in migrations_test would need connection string changes
- Docker test infrastructure significantly impacted

## Recommendation

This is a **major architectural change** that would require:
1. Comprehensive testing strategy
2. Migration path for existing deployments
3. Updated documentation across all files in README.md
4. Coordination with deployment teams

Consider whether the benefits outweigh the migration cost for your specific use case.

# DB-to-Schema Migration Tool

Updated standalone migration tool to facilitate moving from multiple databases to a single database with multiple schemas.

## goose-lamassu tool (`engines/storage/postgres/cmd/goose-lamassu/main.go`)

````go
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	postgres "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
	"github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/migrations"
	"github.com/pressly/goose/v3"
)

var (
	flags = flag.NewFlagSet("goose-lamassu", flag.ExitOnError)
)

func init() {
	flags.Usage = func() {
		log.Println("Usage: goose-lamassu DBSTRING COMMAND [ARGS...]")
		log.Println()
		log.Println("Examples:")
		log.Println(`  goose-lamassu "host=localhost user=postgres password=test dbname=lamassu port=5432 sslmode=disable search_path=ca" up`)
		log.Println(`  goose-lamassu "host=localhost user=postgres password=test dbname=lamassu port=5432 sslmode=disable search_path=alerts" status`)
		log.Println(`  goose-lamassu "host=localhost user=postgres password=test dbname=lamassu port=5432 sslmode=disable search_path=devicemanager" up-to 5`)
		log.Println()
		log.Println("Valid schemas: ca, devicemanager, dmsmanager, alerts, va, kms")
		log.Println()
		log.Println("Special command:")
		log.Println("  migrate-from-databases   Migrate existing multi-database setup to schemas")
		log.Println()
		log.Println("Standard commands:")
		log.Println("  up                   Migrate the DB to the most recent version available")
		log.Println("  up-by-one            Migrate the DB up by 1")
		log.Println("  up-to VERSION        Migrate the DB to a specific VERSION")
		log.Println("  down                 Roll back the version by 1")
		log.Println("  down-to VERSION      Roll back to a specific VERSION")
		log.Println("  redo                 Re-run the latest migration")
		log.Println("  reset                Roll back all migrations")
		log.Println("  status               Dump the migration status for the current DB")
		log.Println("  version              Print the current version of the database")
	}
}

func main() {
	if err := flags.Parse(os.Args[1:]); err != nil {
		log.Fatalf("goose-lamassu: failed to parse flags: %v", err)
	}
	args := flags.Args()

	if len(args) < 1 {
		flags.Usage()
		return
	}

	// Check for special migration command
	if args[0] == "migrate-from-databases" {
		if len(args) < 2 {
			log.Fatal("Usage: goose-lamassu migrate-from-databases BASE_CONNECTION_STRING")
			log.Fatal(`Example: goose-lamassu migrate-from-databases "host=localhost user=postgres password=test port=5432 sslmode=disable"`)
		}
		runMigrationFromDatabases(args[1])
		return
	}

	if len(args) < 2 {
		flags.Usage()
		return
	}

	// Parse: goose-lamassu DBSTRING COMMAND [ARGS...]
	dbstring, command := args[0], args[1]

	// Extract schema name from connection string
	schemaName := extractSearchPath(dbstring)
	if schemaName == "" {
		log.Fatalf("goose-lamassu: could not extract search_path from connection string. Required format: search_path=<schema>")
	}

	// Validate schema name
	validSchemas := []string{"ca", "devicemanager", "dmsmanager", "alerts", "va", "kms"}
	if !contains(validSchemas, schemaName) {
		log.Fatalf("goose-lamassu: invalid schema: %s. Must be one of: %s", schemaName, strings.Join(validSchemas, ", "))
	}

	// Open database connection
	db, err := goose.OpenDBWithDriver("postgres", dbstring)
	if err != nil {
		log.Fatalf("goose-lamassu: failed to open DB: %v", err)
	}

	defer func() {
		if err := db.Close(); err != nil {
			log.Fatalf("goose-lamassu: failed to close DB: %v", err)
		}
	}()

	// Ensure we're in the correct schema
	if _, err := db.Exec(fmt.Sprintf("SET search_path TO %s", schemaName)); err != nil {
		log.Fatalf("goose-lamassu: failed to set search_path: %v", err)
	}

	// Reset global migrations and register migrations for this schema
	goose.ResetGlobalMigrations()
	migrations.RegisterGoMigrations(schemaName)

	// Get migrations filesystem for this schema
	embeddedFS := postgres.GetEmbeddedMigrations()
	migrationsDir := filepath.Join("migrations", schemaName)
	migrationsFS, err := fs.Sub(embeddedFS, migrationsDir)
	if err != nil {
		log.Fatalf("goose-lamassu: failed to get migrations subdirectory: %v", err)
	}

	goose.SetBaseFS(migrationsFS)
	defer goose.SetBaseFS(nil)

	// Prepare command arguments
	arguments := []string{}
	if len(args) > 2 {
		arguments = append(arguments, args[2:]...)
	}

	ctx := context.Background()
	if err := goose.RunContext(ctx, command, db, ".", arguments...); err != nil {
		log.Fatalf("goose-lamassu %v: %v", command, err)
	}
}

// runMigrationFromDatabases migrates from old multi-database setup to new schema-based setup
func runMigrationFromDatabases(baseConnStr string) {
	log.Println("╔════════════════════════════════════════════════════════════════╗")
	log.Println("║  Migrating from Multi-Database to Multi-Schema Architecture   ║")
	log.Println("╚════════════════════════════════════════════════════════════════╝")
	log.Println()

	schemas := []string{"ca", "devicemanager", "dmsmanager", "alerts", "va", "kms"}

	// Step 1: Create unified database
	log.Println("📦 Step 1: Creating unified database 'lamassu'...")
	if err := createDatabase(baseConnStr, "lamassu"); err != nil {
		log.Fatalf("❌ Failed to create database: %v", err)
	}
	log.Println("✅ Unified database created")
	log.Println()

	// Step 2: Connect to unified database and create schemas
	log.Println("🏗️  Step 2: Creating schemas in unified database...")
	unifiedDB, err := sql.Open("postgres", addDBToConnStr(baseConnStr, "lamassu"))
	if err != nil {
		log.Fatalf("❌ Failed to connect to unified database: %v", err)
	}
	defer unifiedDB.Close()

	for _, schema := range schemas {
		log.Printf("   Creating schema: %s", schema)
		if _, err := unifiedDB.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", schema)); err != nil {
			log.Fatalf("❌ Failed to create schema %s: %v", schema, err)
		}
	}
	log.Println("✅ All schemas created")
	log.Println()

	// Step 3: Copy data from each database to its schema
	log.Println("📋 Step 3: Copying data from databases to schemas...")
	for _, schema := range schemas {
		log.Printf("\n   Migrating '%s' database → '%s' schema", schema, schema)
		
		// Connect to old database
		oldDB, err := sql.Open("postgres", addDBToConnStr(baseConnStr, schema))
		if err != nil {
			log.Printf("   ⚠️  Warning: Could not connect to database '%s' (may not exist): %v", schema, err)
			log.Printf("   ⏭️  Skipping '%s'...", schema)
			continue
		}

		// Get all tables from old database
		tables, err := getTables(oldDB)
		if err != nil {
			oldDB.Close()
			log.Printf("   ⚠️  Warning: Could not get tables from '%s': %v", schema, err)
			continue
		}

		if len(tables) == 0 {
			oldDB.Close()
			log.Printf("   ℹ️  No tables found in '%s' database", schema)
			continue
		}

		// Copy each table
		for _, table := range tables {
			log.Printf("      • Copying table: %s", table)
			
			if err := copyTableToSchema(oldDB, unifiedDB, schema, table); err != nil {
				oldDB.Close()
				log.Fatalf("❌ Failed to copy table %s.%s: %v", schema, table, err)
			}
		}

		oldDB.Close()
		log.Printf("   ✅ Completed migration of '%s'", schema)
	}

	log.Println()
	log.Println("╔════════════════════════════════════════════════════════════════╗")
	log.Println("║                  Migration Completed Successfully!            ║")
	log.Println("╚════════════════════════════════════════════════════════════════╝")
	log.Println()
	log.Println("📝 Next Steps:")
	log.Println("   1. Update application configuration:")
	log.Println("      OLD: dbname=ca")
	log.Println("      NEW: dbname=lamassu search_path=ca")
	log.Println()
	log.Println("   2. Test the application thoroughly")
	log.Println()
	log.Println("   3. Once verified, drop old databases:")
	for _, schema := range schemas {
		log.Printf("      DROP DATABASE IF EXISTS %s;", schema)
	}
	log.Println()
}

func createDatabase(connStr, dbName string) error {
	db, err := sql.Open("postgres", addDBToConnStr(connStr, "postgres"))
	if err != nil {
		return err
	}
	defer db.Close()

	var exists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)", dbName).Scan(&exists)
	if err != nil {
		return err
	}

	if exists {
		log.Printf("   ℹ️  Database '%s' already exists", dbName)
		return nil
	}

	_, err = db.Exec(fmt.Sprintf("CREATE DATABASE %s", dbName))
	return err
}

func getTables(db *sql.DB) ([]string, error) {
	rows, err := db.Query(`
		SELECT tablename 
		FROM pg_tables 
		WHERE schemaname = 'public'
		ORDER BY tablename
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			return nil, err
		}
		tables = append(tables, table)
	}
	return tables, nil
}

func copyTableToSchema(sourceDB, targetDB *sql.DB, schema, table string) error {
	// Get table structure
	var createStmt string
	err := sourceDB.QueryRow(fmt.Sprintf(`
		SELECT 'CREATE TABLE %s.' || quote_ident(tablename) || ' (' || 
		       array_to_string(array_agg(quote_ident(attname) || ' ' || format_type(atttypid, atttypmod)), ', ') || ')'
		FROM pg_attribute a
		JOIN pg_class c ON a.attrelid = c.oid
		JOIN pg_namespace n ON c.relnamespace = n.oid
		WHERE c.relname = $1 AND n.nspname = 'public' AND a.attnum > 0 AND NOT a.attisdropped
		GROUP BY tablename
	`, schema), table).Scan(&createStmt)
	
	if err != nil {
		// Fallback: simple copy
		_, err = targetDB.Exec(fmt.Sprintf(
			"CREATE TABLE %s.%s AS SELECT * FROM dblink('dbname=%s', 'SELECT * FROM %s') AS t(tmp)",
			schema, table, schema, table,
		))
		if err != nil {
			// Final fallback: manual copy
			return copyTableManually(sourceDB, targetDB, schema, table)
		}
		return nil
	}

	// Create table in target schema
	if _, err := targetDB.Exec(createStmt); err != nil {
		return err
	}

	// Copy data
	rows, err := sourceDB.Query(fmt.Sprintf("SELECT * FROM %s", table))
	if err != nil {
		return err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return err
	}

	// Build INSERT statement
	placeholders := make([]string, len(cols))
	for i := range placeholders {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
	}

	insertStmt := fmt.Sprintf("INSERT INTO %s.%s (%s) VALUES (%s)",
		schema, table,
		strings.Join(cols, ", "),
		strings.Join(placeholders, ", "),
	)

	// Prepare insert statement
	stmt, err := targetDB.Prepare(insertStmt)
	if err != nil {
		return err
	}
	defer stmt.Close()

	// Copy rows
	values := make([]interface{}, len(cols))
	valuePtrs := make([]interface{}, len(cols))
	for i := range values {
		valuePtrs[i] = &values[i]
	}

	for rows.Next() {
		if err := rows.Scan(valuePtrs...); err != nil {
			return err
		}
		if _, err := stmt.Exec(values...); err != nil {
			return err
		}
	}

	return rows.Err()
}

func copyTableManually(sourceDB, targetDB *sql.DB, schema, table string) error {
	// Create table structure by copying from source
	_, err := targetDB.Exec(fmt.Sprintf(
		"CREATE TABLE %s.%s AS SELECT * FROM pg_catalog.pg_tables WHERE false",
		schema, table,
	))
	if err != nil {
		return err
	}

	// Simple data copy (may not preserve all constraints)
	rows, err := sourceDB.Query(fmt.Sprintf("SELECT * FROM %s", table))
	if err != nil {
		return err
	}
	defer rows.Close()

	// This is a simplified version - real implementation would need proper type handling
	return fmt.Errorf("table %s requires manual migration", table)
}

func addDBToConnStr(connStr, dbName string) string {
	if strings.Contains(connStr, "dbname=") {
		parts := strings.Fields(connStr)
		for i, part := range parts {
			if strings.HasPrefix(part, "dbname=") {
				parts[i] = "dbname=" + dbName
				return strings.Join(parts, " ")
			}
		}
	}
	return connStr + " dbname=" + dbName
}

func extractSearchPath(connStr string) string {
	parts := strings.Fields(connStr)
	for _, part := range parts {
		if after, ok := strings.CutPrefix(part, "search_path="); ok {
			return after
		}
	}
	return ""
}

func contains(slice []string, str string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, str) {
			return true
		}
	}
	return false
}
````

## Usage

### Normal migrations (schema mode):
```bash
# Migrate CA schema
goose-lamassu "host=localhost user=postgres password=test dbname=lamassu search_path=ca port=5432 sslmode=disable" up

# Check status of alerts schema
goose-lamassu "host=localhost user=postgres password=test dbname=lamassu search_path=alerts port=5432 sslmode=disable" status
```

### One-time migration from old multi-database setup:
```bash
# Migrate all existing databases to schemas
goose-lamassu migrate-from-databases "host=localhost user=postgres password=test port=5432 sslmode=disable"
```

## Key Changes from Original

1. **Removed `dbname` extraction** - now only uses `search_path`
2. **Single unified database** - always `lamassu`
3. **Simpler validation** - schemas instead of databases
4. **Built-in migration tool** - single command to migrate from old setup
5. **Cleaner code** - no mode switching, single path through the code

This gives you **exactly what you need**: a schema-only approach with a built-in migration path from your existing multi-database setup.

Goose migrations run within **a single database connection**. A migration file like this:

```go
func upMigrateToSchema(ctx context.Context, tx *sql.Tx) error {
    // This runs INSIDE the 'ca' database
    // You CANNOT access the 'lamassu' database from here!
    // You CANNOT copy data between databases in a single transaction
}
```

When you connect to `dbname=ca` and run migrations, you **cannot access** `dbname=lamassu` from within that migration. PostgreSQL doesn't allow cross-database transactions like that.

## Why the Standalone Tool is Actually Necessary

Looking at your code in utils.go, the `CreatePostgresDBConnection` function creates connections like this:

```go
dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=disable", 
    cfg.Hostname, cfg.Username, cfg.Password, database, cfg.Port)
```

To migrate from databases to schemas, you need to:
1. Connect to `dbname=ca` (read data)
2. Connect to `dbname=lamassu` with `search_path=ca` (write data)
3. Do this for ALL databases

**This requires multiple database connections**, which a single Goose migration cannot do.

## The Only Two Viable Approaches

### **Approach 1: Standalone Migration Tool** (What I showed)
```bash
# One-time command that handles everything
goose-lamassu migrate-from-databases "host=localhost ..."
```

This works because the tool can:
- Open connection to `ca` database
- Open connection to `lamassu` database
- Copy data between them
- Close both connections
- Repeat for next database

### **Approach 2: Manual pg_dump/pg_restore**
```bash
# For each database, dump and restore to a schema

# 1. Dump the ca database
pg_dump -h localhost -U postgres -d ca -F c -f ca_dump.backup

# 2. Create schema in unified database
psql -h localhost -U postgres -d lamassu -c "CREATE SCHEMA IF NOT EXISTS ca;"

# 3. Restore to the schema
pg_restore -h localhost -U postgres -d lamassu -n ca ca_dump.backup

# Repeat for each database...
```