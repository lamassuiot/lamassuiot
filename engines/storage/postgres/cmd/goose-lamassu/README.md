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
2. `ca`: certificates reference KMS keys. If `kms` is not migrated yet, it fails with `kms schema not found: migrate the kms schema before the ca schema`. Register legacy keys in KMS before running it with [`ca-to-kms-migration`](../../../../../backend/cmd/ca-to-kms-migration/README.md), which runs on the `ca` schema of earlier versions.
3. `va`: VA roles reference their signer certificates, so it needs `ca` migrated. Fix VA roles whose signer certificate is missing before running it. When several CAs share the signer's key, the migration logs a warning and uses the oldest of them. If `va` is not migrated, VA role and CRL requests fail with `column "crl_signer_certificate_serial_number" of relation "va_role" does not exist`.

Both foreign keys validate existing rows.

`devicemanager`, `dmsmanager` and `alerts` are independent and can be migrated at any point.

### Cross-schema privileges

The `ca` and `va` migrations create foreign keys and read tables that belong to another schema. PostgreSQL checks privileges on those tables for the user that runs the migration, so it needs more than the privileges on its own schema (see [Troubleshooting](#troubleshooting)). If the same user owns every schema, nothing extra is needed.

| Migration (`search_path`) | Other schema | Needs | Used for |
|---|---|---|---|
| `ca` | `kms` | `USAGE` on the schema; `SELECT` and `REFERENCES` on `kms.kms_keys`; `INSERT` on `kms.kms_keys` | The certificate-to-key foreign key, the `certificates_view` view, and the registration of the public keys of deleted CAs |
| `va` | `ca` | `USAGE` on the schema; `SELECT` and `REFERENCES` on `ca.certificates`; `SELECT` on `ca.ca_certificates` | The VA role-to-signer-certificate foreign key and the lookup of each role's signer certificate |

Without them the migration aborts, for example with `permission denied for table certificates` on the `va` foreign key. Earlier schemas are already migrated, so grant the missing privileges and run the failed schema again. For example, for the `va` migration:

```sql
GRANT USAGE ON SCHEMA ca TO migration_user;
GRANT SELECT, REFERENCES ON ca.certificates TO migration_user;
GRANT SELECT ON ca.ca_certificates TO migration_user;
```

The `ca` migration also creates the view `ca.certificates_view`, through which the CA service reads certificates and CAs. The view belongs to the user that ran the migration, so if the CA service connects as a different user, grant that user `SELECT` on the view after migrating `ca`. Without it, every certificate and CA read fails with `permission denied for table certificates_view`.

```sql
GRANT SELECT ON ca.certificates_view TO service_user;
```

The view reads `kms.kms_keys` with its owner's privileges, so the service user needs no privileges on the `kms` schema for this.

To migrate every schema in order:

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
- The PostgreSQL user needs `CREATE` on the database and `SELECT, INSERT, UPDATE, DELETE` on the tables of the schema it migrates. It also needs to be able to create `goose_db_version`. The `ca` and `va` migrations need additional privileges on the `kms` and `ca` schemas: see [Cross-schema privileges](#cross-schema-privileges).
- `permission denied for table certificates` or `permission denied for table kms_keys` during the `va` or `ca` migration: the user lacks `REFERENCES` or `SELECT` on the table of the other schema. Grant it and run that schema again.
