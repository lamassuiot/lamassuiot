# Lamassu PostgreSQL Migration Tool (goose-lamassu)

This is a custom goose binary for managing Lamassu PostgreSQL database migrations independently, without needing to start the full services. It uses the [pressly/goose](https://github.com/pressly/goose) migration framework with embedded SQL and Go migrations.

**Based on**: [goose go-migrations example](https://github.com/pressly/goose/blob/main/examples/go-migrations/main.go)

## Overview

The `goose-lamassu` tool provides direct access to goose's migration commands with Lamassu-specific embedded migrations. It:
- Uses the standard goose command-line interface
- Supports all goose migration commands
- Embeds SQL and Go migrations for all Lamassu databases
- Validates database names against Lamassu's supported databases

## Supported Databases

- `ca` - Certificate Authority database
- `devicemanager` - Device Manager database
- `dmsmanager` - DMS Manager database
- `alerts` - Alerts database
- `va` - Validation Authority database
- `kms` - Key Management Service database

## Building

### Local Binary

From this directory:

```bash
cd engines/storage/postgres/cmd/goose-lamassu
go build -o goose-lamassu
```

Or from the repository root:

```bash
go build -o goose-lamassu ./engines/storage/postgres/cmd/goose-lamassu
```

## Usage

The tool follows the standard goose command-line pattern:

```bash
goose-lamassu DBSTRING COMMAND [ARGS...]
```

Where:
- `DBSTRING` - PostgreSQL connection string (must include `dbname` parameter)
- `COMMAND` - Goose migration command (up, down, status, etc.)
- `ARGS` - Optional arguments for the command (e.g., version number for up-to)

### Available Commands

- `up` - Migrate the DB to the most recent version available
- `up-by-one` - Migrate the DB up by 1
- `up-to VERSION` - Migrate the DB to a specific VERSION
- `down` - Roll back the version by 1
- `down-to VERSION` - Roll back to a specific VERSION
- `redo` - Re-run the latest migration
- `reset` - Roll back all migrations
- `status` - Dump the migration status for the current DB
- `version` - Print the current version of the database

## Examples

### Migrate Up to Latest Version

```bash
./goose-lamassu \
  "host=localhost user=postgres password=test dbname=ca port=5432 sslmode=disable" \
  up
```

### Check Migration Status

```bash
./goose-lamassu \
  "host=localhost user=postgres password=test dbname=alerts port=5432 sslmode=disable" \
  status
```

### Migrate to Specific Version

```bash
./goose-lamassu \
  "host=localhost user=postgres password=test dbname=devicemanager port=5432 sslmode=disable" \
  up-to 5
```

### Roll Back One Migration

```bash
./goose-lamassu \
  "host=localhost user=postgres password=test dbname=va port=5432 sslmode=disable" \
  down
```

### Get Current Version

```bash
./goose-lamassu \
  "host=localhost user=postgres password=test dbname=dmsmanager port=5432 sslmode=disable" \
  version
```

### Using Environment Variables for Connection String

```bash
export DB_HOST=localhost
export DB_USER=postgres
export DB_PASS=test
export DB_PORT=5432

./goose-lamassu \
  "host=$DB_HOST user=$DB_USER password=$DB_PASS dbname=ca port=$DB_PORT sslmode=disable" \
  up
```

## Docker

### Build the Image

The Docker image is built from the **repository root** using the Dockerfile in the `ci` folder:

```bash
cd /path/to/lamassuiot
docker build -f ci/goose-lamassu.dockerfile -t lamassu/goose-lamassu:latest .
```

### Run with Docker

```bash
docker run --rm \
  lamassu/goose-lamassu:latest \
  "host=postgres-host user=postgres password=secret dbname=ca port=5432 sslmode=disable" \
  up
```

### Docker Compose Example

```yaml
version: '3.8'
services:
  migrate:
    image: lamassu/goose-lamassu:latest
    command: >
      "host=postgres user=postgres password=secret dbname=ca port=5432 sslmode=disable"
      up
    depends_on:
      - postgres
```

## Integration with CI/CD

You can integrate this tool into your CI/CD pipeline to apply migrations before deploying services.

### GitLab CI/CD Example

```yaml
migrate-ca:
  stage: deploy
  script:
    - |
      ./goose-lamassu \
        "host=$POSTGRES_HOST user=$POSTGRES_USER password=$POSTGRES_PASSWORD dbname=ca port=5432 sslmode=disable" \
        up
  only:
    - main

migrate-all:
  stage: deploy
  parallel:
    matrix:
      - DB: [ca, devicemanager, dmsmanager, alerts, va, kms]
  script:
    - |
      ./goose-lamassu \
        "host=$POSTGRES_HOST user=$POSTGRES_USER password=$POSTGRES_PASSWORD dbname=$DB port=5432 sslmode=disable" \
        up
  only:
    - main
```

### GitHub Actions Example

```yaml
- name: Run Database Migrations
  run: |
    ./goose-lamassu \
      "host=${{ secrets.POSTGRES_HOST }} user=${{ secrets.POSTGRES_USER }} password=${{ secrets.POSTGRES_PASSWORD }} dbname=ca port=5432 sslmode=disable" \
      up
```

## Direct Goose Usage

Since this tool uses goose directly via `goose.RunContext()`, you have access to all standard goose functionality:

- Migration tracking via `goose_db_version` table
- Transaction support for SQL migrations
- Go migrations with custom logic
- Detailed migration logging
- Rollback capabilities

For more information on goose features and commands, see the [goose documentation](https://github.com/pressly/goose).

## Migration Safety

This tool provides safe migration management:

- Only applies pending migrations (controlled by goose)
- Uses transactions where applicable
- Provides clear logging of all operations
- Shows migration status before applying
- Is idempotent - running it multiple times is safe
- Tracks applied migrations in `goose_db_version` table

## Troubleshooting

### Connection Issues

If you can't connect to PostgreSQL:

1. Verify the hostname and port are correct
2. Check that PostgreSQL is accepting connections
3. Ensure the user has proper permissions
4. Verify network connectivity
5. Check that the database exists

### Permission Issues

The PostgreSQL user needs:

- CREATE permission on the database
- SELECT, INSERT, UPDATE, DELETE permissions on tables
- Ability to create the `goose_db_version` table

### Invalid Database Name

The tool validates that the database name is one of the supported Lamassu databases. If you see an "invalid database" error, ensure the `dbname` parameter in your connection string matches one of: ca, devicemanager, dmsmanager, alerts, va, kms.

### Migration Failures

If a migration fails:

1. Check the logs for specific error messages
2. Verify the database schema state
3. Check the `goose_db_version` table to see which migrations have been applied
4. You may need to manually fix the database state before retrying
5. Use the `status` command to see the current migration state

## Differences from Standard Goose

This custom binary differs from the standard goose CLI in a few ways:

- Automatically registers Go migrations for the specified Lamassu database
- Validates database names against Lamassu's supported databases
- Uses embedded migrations (no need for migration files on disk)
- Extracts the database name from the connection string

## Support

For issues or questions:

- Check the [goose documentation](https://github.com/pressly/goose) for command help
- Refer to the main Lamassu documentation
- Open an issue in the Lamassu repository
