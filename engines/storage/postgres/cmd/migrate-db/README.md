# PostgreSQL Database Migration Tool

This tool allows you to independently apply database migrations for Lamassu without needing to start the full services.

## Overview

The migration tool provides a standalone way to:
- Apply migrations to a specific database
- Apply migrations to all Lamassu databases at once
- Check the migration status of databases

## Supported Databases

- `ca` - Certificate Authority database
- `devicemanager` - Device Manager database
- `dmsmanager` - DMS Manager database
- `alerts` - Alerts database
- `va` - Validation Authority database
- `kms` - Key Management Service database

## Building

From the root of the repository:

```bash
cd engines/storage/postgres/cmd/migrate-db
go build -o migrate-db
```

Or build from anywhere:

```bash
go build -o migrate-db ./engines/storage/postgres/cmd/migrate-db
```

## Usage

### Command Line Flags

- `-hostname` - PostgreSQL hostname (required)
- `-port` - PostgreSQL port (default: 5432)
- `-username` - PostgreSQL username (required)
- `-password` - PostgreSQL password (required)
- `-database` - Database name to migrate (ca, devicemanager, dmsmanager, alerts, va, kms)
- `-all` - Migrate all Lamassu databases
- `-status` - Show migration status without applying migrations
- `-log-level` - Log level (trace, debug, info, warn, error) (default: info)

### Environment Variables

Instead of using command line flags, you can set environment variables:

- `POSTGRES_HOSTNAME` - PostgreSQL hostname
- `POSTGRES_PORT` - PostgreSQL port
- `POSTGRES_USERNAME` - PostgreSQL username
- `POSTGRES_PASSWORD` - PostgreSQL password

## Examples

### Migrate a Specific Database

```bash
./migrate-db \
  -hostname=localhost \
  -username=postgres \
  -password=secret \
  -database=ca
```

### Migrate All Databases

```bash
./migrate-db \
  -hostname=localhost \
  -username=postgres \
  -password=secret \
  -all
```

### Check Migration Status

```bash
./migrate-db \
  -hostname=localhost \
  -username=postgres \
  -password=secret \
  -database=ca \
  -status
```

### Check Status of All Databases

```bash
./migrate-db \
  -hostname=localhost \
  -username=postgres \
  -password=secret \
  -all \
  -status
```

### Using Environment Variables

```bash
export POSTGRES_HOSTNAME=localhost
export POSTGRES_USERNAME=postgres
export POSTGRES_PASSWORD=secret

./migrate-db -database=ca
```

### With Docker

You can run the migration tool in a Docker container:

```bash
docker run --rm \
  -e POSTGRES_HOSTNAME=postgres-host \
  -e POSTGRES_USERNAME=postgres \
  -e POSTGRES_PASSWORD=secret \
  lamassu/migrate-db:latest \
  -database=ca
```

## Integration with CI/CD

You can integrate this tool into your CI/CD pipeline to apply migrations before deploying services:

```yaml
# Example GitLab CI/CD
migrate:
  stage: deploy
  script:
    - ./migrate-db -hostname=$POSTGRES_HOST -username=$POSTGRES_USER -password=$POSTGRES_PASSWORD -all
  only:
    - main
```

```yaml
# Example GitHub Actions
- name: Run Database Migrations
  run: |
    ./migrate-db -hostname=${{ secrets.POSTGRES_HOST }} \
                 -username=${{ secrets.POSTGRES_USER }} \
                 -password=${{ secrets.POSTGRES_PASSWORD }} \
                 -all
```

## Programmatic Usage

You can also use the migration functions programmatically in your own Go code:

```go
package main

import (
    "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
    lconfig "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/config"
    postgres "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
    "github.com/sirupsen/logrus"
)

func main() {
    logger := helpers.SetupLogger("info", "PostgreSQL", "Migration")
    
    cfg := lconfig.PostgresPSEConfig{
        Hostname: "localhost",
        Port:     5432,
        Username: "postgres",
        Password: "secret",
    }
    
    // Migrate a specific database
    if err := postgres.MigrateDatabase(logger, cfg, "ca"); err != nil {
        logger.Fatalf("Migration failed: %v", err)
    }
    
    // Or migrate all databases
    if err := postgres.MigrateAllDatabases(logger, cfg); err != nil {
        logger.Fatalf("Migration failed: %v", err)
    }
    
    // Or check version
    current, target, err := postgres.GetDatabaseVersion(logger, cfg, "ca")
    if err != nil {
        logger.Fatalf("Failed to get version: %v", err)
    }
    logger.Infof("Current: %d, Target: %d", current, target)
}
```

## Migration Safety

The tool:
- Only applies pending migrations (never rolls back)
- Uses transactions where applicable
- Provides clear logging of all operations
- Shows current and target versions before migrating
- Is idempotent - running it multiple times is safe

## Troubleshooting

### Connection Issues

If you can't connect to PostgreSQL:
1. Verify the hostname and port are correct
2. Check that PostgreSQL is accepting connections
3. Ensure the user has proper permissions
4. Verify network connectivity

### Permission Issues

The PostgreSQL user needs:
- CREATE permission on the database
- SELECT, INSERT, UPDATE, DELETE permissions on tables
- Ability to create the `goose_db_version` table

### Migration Failures

If a migration fails:
1. Check the logs for specific error messages
2. Verify the database schema state
3. The goose migration framework tracks which migrations have been applied in the `goose_db_version` table
4. You may need to manually fix the database state before retrying

## Support

For issues or questions, please refer to the main Lamassu documentation or open an issue in the repository.
