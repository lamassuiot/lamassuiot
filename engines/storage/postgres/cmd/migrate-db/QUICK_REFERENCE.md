# Database Migration - Quick Reference

## TL;DR

You can now run database migrations independently without starting Lamassu services.

## Quick Start

### Build the Tool

```bash
cd engines/storage/postgres/cmd/migrate-db
go build -o migrate-db
```

### Run Migrations

```bash
# All databases
./migrate-db -hostname=localhost -username=postgres -password=secret -all

# Single database
./migrate-db -hostname=localhost -username=postgres -password=secret -database=ca

# Check status
./migrate-db -hostname=localhost -username=postgres -password=secret -all -status
```

### Configure Services to Skip Auto-Migration

```yaml
# service-config.yml
storage:
  provider: postgres
  config:
    hostname: postgres.example.com
    port: 5432
    username: lamassu
    password: ${POSTGRES_PASSWORD}
    skip_migrations: true  # ADD THIS LINE
```

## Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `-hostname` | PostgreSQL hostname | *required* |
| `-port` | PostgreSQL port | 5432 |
| `-username` | PostgreSQL username | *required* |
| `-password` | PostgreSQL password | *required* |
| `-database` | Database to migrate | - |
| `-all` | Migrate all databases | false |
| `-status` | Show status only | false |
| `-log-level` | Log verbosity | info |

## Environment Variables

Set these to avoid passing credentials as flags:

```bash
export POSTGRES_HOSTNAME=localhost
export POSTGRES_PORT=5432
export POSTGRES_USERNAME=postgres
export POSTGRES_PASSWORD=secret

./migrate-db -all
```

## Supported Databases

- `ca` - Certificate Authority
- `devicemanager` - Device Manager  
- `dmsmanager` - DMS Manager
- `alerts` - Alerts
- `va` - Validation Authority
- `kms` - Key Management Service

## Common Workflows

### Docker Compose

```yaml
services:
  migrate:
    image: lamassu/migrate-db:latest
    environment:
      POSTGRES_HOSTNAME: postgres
      POSTGRES_USERNAME: lamassu
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    command: ["-all"]
    
  ca-service:
    image: lamassu/ca:latest
    environment:
      POSTGRES_SKIP_MIGRATIONS: "true"
    depends_on:
      migrate:
        condition: service_completed_successfully
```

### Kubernetes Job

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: db-migrate
spec:
  template:
    spec:
      containers:
      - name: migrate
        image: lamassu/migrate-db:latest
        args: ["-all"]
        env:
        - name: POSTGRES_HOSTNAME
          value: postgres-service
        - name: POSTGRES_USERNAME
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: username
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: password
      restartPolicy: OnFailure
```

### CI/CD Pipeline

```bash
# GitLab CI / GitHub Actions
migrate-db -hostname=$DB_HOST -username=$DB_USER -password=$DB_PASS -all
```

## Programmatic Usage

```go
import postgres "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"

cfg := lconfig.PostgresPSEConfig{
    Hostname: "localhost",
    Port:     5432,
    Username: "postgres",
    Password: "secret",
}

// Migrate all
postgres.MigrateAllDatabases(logger, cfg)

// Migrate one
postgres.MigrateDatabase(logger, cfg, "ca")

// Check version
current, target, _ := postgres.GetDatabaseVersion(logger, cfg, "ca")
```

## Troubleshooting

### Can't connect to database

```bash
# Check connection
psql -h localhost -U postgres -d ca -c "SELECT 1;"
```

### Check migration status

```bash
./migrate-db -hostname=localhost -username=postgres -password=secret -database=ca -status
```

### Check applied migrations in database

```sql
SELECT * FROM goose_db_version ORDER BY id;
```

## More Information

- Full documentation: `README.md`
- Detailed workflows: `MANUAL_MIGRATION_GUIDE.md`
- Summary of changes: `MIGRATION_CHANGES_SUMMARY.md`
