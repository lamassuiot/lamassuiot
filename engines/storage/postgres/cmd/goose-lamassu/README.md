# goose-lamassu

Standalone [goose](https://github.com/pressly/goose) binary that applies the Lamassu PostgreSQL migrations (embedded SQL and Go migrations), without starting the services.

In deployments the migrations are run by the Helm chart as a Kubernetes Job. This document only describes how to apply them with the tool.

## Usage

```bash
goose-lamassu DBSTRING COMMAND [ARGS...]
```

- `DBSTRING`: PostgreSQL connection string. Since 4.0.0 all services share the `pki` database and each one has its own schema, so it must include `dbname=pki` and `search_path=<schema>`, where `<schema>` is one of the supported schemas below. The tool exits if `search_path` is missing or is not a supported schema. It does not validate `dbname`, so check it before running the command.
- `COMMAND`: a goose command. The most useful are `up`, `up-to VERSION`, `down`, `status` and `version`.

```bash
./goose-lamassu \
  "host=localhost user=postgres password=test dbname=pki search_path=ca port=5432 sslmode=disable" \
  up
```

## Supported schemas

`ca`, `devicemanager`, `dmsmanager`, `alerts`, `va`, `kms`

## Migration order

Migrate **`kms` → `ca` → `va`**, one at a time. Never run them in parallel.

1. `kms`
2. `ca`: certificates reference KMS keys. If `kms` is not migrated yet, it fails with `kms schema not found: migrate the kms schema before the ca schema`. Register legacy keys in KMS before running it.
3. `va`: VA roles reference their signer certificates, so it needs `ca` migrated. Fix VA roles whose signer certificate is missing before running it. When several CAs share the signer's key, the migration logs a warning and uses the oldest of them. If `va` is not migrated, VA role and CRL requests fail with `column "crl_signer_certificate_serial_number" of relation "va_role" does not exist`.

Both foreign keys validate existing rows.

`devicemanager`, `dmsmanager` and `alerts` are independent and can be migrated at any point.

```bash
for schema in kms ca va devicemanager dmsmanager alerts; do
  ./goose-lamassu \
    "host=$DB_HOST user=$DB_USER password=$DB_PASS dbname=pki search_path=$schema port=5432 sslmode=disable" \
    up || break
done
```

## Build

From the repository root:

```bash
go build -o goose-lamassu ./engines/storage/postgres/cmd/goose-lamassu
```

Or the container image (also from the repository root):

```bash
docker build -f ci/lamassu-db-migration.dockerfile -t lamassu/lamassu-db-migration:latest .

docker run --rm lamassu/lamassu-db-migration:latest \
  "host=postgres-host user=postgres password=secret dbname=pki search_path=kms port=5432 sslmode=disable" \
  up
```

## Troubleshooting

- A failed migration: run `status` and check the `goose_db_version` table to see what was applied. Fix the database state before retrying.
- "could not extract search_path from connection string" error: the connection string has no `search_path=<schema>`.
- "invalid schema" error: `search_path` is not one of the supported schemas.
- The PostgreSQL user needs `CREATE` on the database and `SELECT, INSERT, UPDATE, DELETE` on its tables. It also needs to be able to create `goose_db_version`.
