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

When upgrading from 3.8, run [`ca-to-kms-migration`](../../../../../backend/cmd/ca-to-kms-migration/README.md) first: it registers in the KMS the keys of the existing CAs, which the `ca` migration needs, and it runs on the `kms` and `ca` schemas of 3.8. Then migrate **`kms` → `ca` → `va`**, one at a time. Never run them in parallel.

1. `kms`
2. `ca`: certificates reference KMS keys. If `kms` is not migrated yet, it fails with `kms schema not found: migrate the kms schema before the ca schema`. If a CA key is not in the KMS, it fails with `unresolved certificate key`: run `ca-to-kms-migration` and migrate again.
3. `va`: CRL settings reference their signer certificates and KMS keys and are keyed by CA ID, so it needs both `kms` and `ca` migrated. Before running it, every SKI must belong to a single CA, every VA role must have a signer certificate with a key, and no CA ID may contain `/` or equal the SKI of another role; the migration fails and lists the affected rows otherwise. If `va` is not migrated, CRL settings and CRL requests fail with `relation "crl_settings" does not exist`.

The foreign keys validate existing rows.

`devicemanager`, `dmsmanager` and `alerts` are independent and can be migrated at any point.

### Cross-schema privileges

The `ca` and `va` migrations create foreign keys and read tables that belong to another schema, and the `kms` migration may update them. PostgreSQL checks privileges on those tables for the user that runs the migration, so it needs more than the privileges on its own schema (see [Troubleshooting](#troubleshooting)). If the same user owns every schema, nothing extra is needed.

| Migration (`search_path`) | Other schema | Needs | Used for |
|---|---|---|---|
| `ca` | `kms` | `USAGE` on the schema; `SELECT` and `REFERENCES` on `kms.kms_keys`; `INSERT` on `kms.kms_keys` | The certificate-to-key foreign key, the `certificates_view` view, and the registration of the public keys of deleted CAs |
| `va` | `ca` | `USAGE` on the schema; `SELECT` and `REFERENCES` on `ca.certificates`; `SELECT` on `ca.ca_certificates` | The VA role-to-signer-certificate foreign key and the lookup of each role's signer certificate |
| `va` | `kms` | `USAGE` on the schema; `SELECT` and `REFERENCES` on `kms.kms_keys` | The CRL signer key lookup and foreign key |
| `kms` | `ca`, `va` | Only when the `ca` and `va` schemas are already migrated: `USAGE` on both schemas; `SELECT` and `UPDATE` on `ca.certificates` and `va.crl_settings` | Moving the references of certificates and CRL signers to the surviving row when the key identity migration removes a duplicate key. Upgrading from 3.8 in the documented order (`kms` first) does not need them, and the migration names the missing privilege if it does |

Without them the migration aborts, for example with `permission denied for table certificates` on the `va` foreign key. Earlier schemas are already migrated, so grant the missing privileges and run the failed schema again. For example, for the `va` migration:

```sql
GRANT USAGE ON SCHEMA ca TO migration_user;
GRANT SELECT, REFERENCES ON ca.certificates TO migration_user;
GRANT SELECT ON ca.ca_certificates TO migration_user;
GRANT USAGE ON SCHEMA kms TO migration_user;
GRANT SELECT, REFERENCES ON kms.kms_keys TO migration_user;
```

The `ca` migration also creates the view `ca.certificates_view`, through which the CA service reads certificates and CAs. The view belongs to the user that ran the migration, so if the CA service connects as a different user, grant that user `SELECT` on the view after migrating `ca`. Without it, every certificate and CA read fails with `permission denied for table certificates_view`.

```sql
GRANT SELECT ON ca.certificates_view TO service_user;
```

The view reads `kms.kms_keys` with its owner's privileges, so the service user needs no privileges on the `kms` schema for this.

The CA service also reads `va.crl_settings` when it deletes a CA, to check that no ACTIVE CRL settings still retain the key. If the CA service connects as a different user from the one that ran the migrations, grant that user the privileges below after migrating `va`. Without them, deleting any CA that has a crypto engine fails with `permission denied for schema va` (or `for table crl_settings`), before the CA service can tell whether a final CRL is pending. Installations without the `va` schema migrated need nothing.

```sql
GRANT USAGE ON SCHEMA va TO service_user;
GRANT SELECT ON va.crl_settings TO service_user;
```

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
- The PostgreSQL user needs `CREATE` on the database and `SELECT, INSERT, UPDATE, DELETE` on the tables of the schema it migrates. It also needs to be able to create `goose_db_version`. The `ca`, `va` and `kms` migrations may need additional privileges on other schemas: see [Cross-schema privileges](#cross-schema-privileges).
- `permission denied for table certificates` or `permission denied for table kms_keys` during the `va` or `ca` migration: the user lacks `REFERENCES` or `SELECT` on the table of the other schema. Grant it and run that schema again.
