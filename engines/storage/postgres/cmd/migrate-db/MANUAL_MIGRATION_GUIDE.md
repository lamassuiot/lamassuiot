# Example Configuration with Manual Migrations

This document shows how to configure Lamassu services to skip automatic migrations and use the standalone migration tool instead.

## Service Configuration

When you want to run migrations separately from your services, add the `skip_migrations: true` option to your PostgreSQL storage configuration:

```yaml
# Example: ca-service.yml
storage:
  provider: postgres
  config:
    hostname: postgres.example.com
    port: 5432
    username: lamassu
    password: ${POSTGRES_PASSWORD}
    skip_migrations: true  # Disable automatic migrations
```

## Workflow

### 1. Run Migrations First

Before starting your services, run the migration tool:

```bash
# Migrate all databases
./migrate-db \
  -hostname=postgres.example.com \
  -username=lamassu \
  -password=${POSTGRES_PASSWORD} \
  -all

# Or migrate specific database
./migrate-db \
  -hostname=postgres.example.com \
  -username=lamassu \
  -password=${POSTGRES_PASSWORD} \
  -database=ca
```

### 2. Start Services

Once migrations are complete, start your services:

```bash
./ca-service -config ca-service.yml
```

The services will connect to the database without attempting to run migrations.

## Benefits

1. **Controlled Deployment**: Run migrations as a separate deployment step
2. **Monitoring**: Track migration progress independently  
3. **Rollback Capability**: Easier to manage if migration fails
4. **CI/CD Integration**: Integrate into your pipeline as a separate stage
5. **Security**: Migration credentials can be different from service credentials
6. **Downtime Management**: Coordinate migrations with service downtime

## Docker Compose Example

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: lamassu
      POSTGRES_USER: lamassu
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    ports:
      - "5432:5432"

  # Run migrations as an init container
  migrate:
    image: lamassu/migrate-db:latest
    environment:
      POSTGRES_HOSTNAME: postgres
      POSTGRES_USERNAME: lamassu
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    command: ["-all"]
    depends_on:
      - postgres

  # CA Service
  ca-service:
    image: lamassu/ca:latest
    environment:
      STORAGE_PROVIDER: postgres
      POSTGRES_HOSTNAME: postgres
      POSTGRES_USERNAME: lamassu
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_SKIP_MIGRATIONS: "true"
    depends_on:
      migrate:
        condition: service_completed_successfully
    ports:
      - "8080:8080"

  # Device Manager Service
  device-manager:
    image: lamassu/device-manager:latest
    environment:
      STORAGE_PROVIDER: postgres
      POSTGRES_HOSTNAME: postgres
      POSTGRES_USERNAME: lamassu
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_SKIP_MIGRATIONS: "true"
    depends_on:
      migrate:
        condition: service_completed_successfully
    ports:
      - "8081:8081"
```

## Kubernetes Example

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: lamassu-db-migrate
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
              name: postgres-secret
              key: username
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: postgres-secret
              key: password
      restartPolicy: OnFailure
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ca-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: ca-service
  template:
    metadata:
      labels:
        app: ca-service
    spec:
      containers:
      - name: ca
        image: lamassu/ca:latest
        env:
        - name: STORAGE_PROVIDER
          value: postgres
        - name: POSTGRES_HOSTNAME
          value: postgres-service
        - name: POSTGRES_USERNAME
          valueFrom:
            secretKeyRef:
              name: postgres-secret
              key: username
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: postgres-secret
              key: password
        - name: POSTGRES_SKIP_MIGRATIONS
          value: "true"
```

## CI/CD Pipeline Example

### GitLab CI

```yaml
stages:
  - migrate
  - deploy

migrate-db:
  stage: migrate
  image: lamassu/migrate-db:latest
  script:
    - migrate-db -hostname=$DB_HOST -username=$DB_USER -password=$DB_PASSWORD -all
  only:
    - main

deploy-services:
  stage: deploy
  script:
    - kubectl apply -f k8s/
  only:
    - main
  needs:
    - migrate-db
```

### GitHub Actions

```yaml
name: Deploy

on:
  push:
    branches: [main]

jobs:
  migrate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Run Database Migrations
        run: |
          docker run --rm \
            -e POSTGRES_HOSTNAME=${{ secrets.DB_HOST }} \
            -e POSTGRES_USERNAME=${{ secrets.DB_USER }} \
            -e POSTGRES_PASSWORD=${{ secrets.DB_PASSWORD }} \
            lamassu/migrate-db:latest \
            -all

  deploy:
    needs: migrate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Deploy Services
        run: |
          kubectl apply -f k8s/
```

## Production Best Practices

1. **Backup First**: Always backup your database before running migrations
2. **Test in Staging**: Run migrations in a staging environment first
3. **Monitor**: Watch migration logs for any errors
4. **Version Control**: Track which migration version is deployed
5. **Rollback Plan**: Have a plan to rollback if needed
6. **Separate Credentials**: Use different credentials for migrations vs services
7. **Audit**: Log all migration executions

## Troubleshooting

### Services fail to start after migration

Check that:
- Migrations completed successfully
- All required databases were migrated
- Database schema matches expected version

### Migration tool can't connect

Verify:
- Database host and port are correct
- Credentials are valid
- Network connectivity
- PostgreSQL is accepting connections

### Partial migration failure

Check the `goose_db_version` table to see which migrations were applied:

```sql
SELECT * FROM goose_db_version ORDER BY id;
```
