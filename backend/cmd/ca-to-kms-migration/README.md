# CA-to-KMS Key Migration Tool

## Motivation

The KMS service was introduced as an independent service in version 3.7.0 of Lamassu IoT. In earlier versions, private keys were managed exclusively by the crypto engine (filesystem, PKCS#11, Vault KV2, AWS KMS, etc.) and there was no separate KMS database table to track them.

When upgrading from an older installation, each CA certificate of type `MANAGED` or `IMPORTED_WITH_KEY` has a private key stored in the crypto engine under its `subject_key_id`. That key has no corresponding row in the `kms_keys` table of the KMS storage (the `kms` schema of the `pki` database in 4.0.0). As a result:

- The KMS service is unaware of those keys and cannot manage or list them.
- The certificates of the CA cannot reference those keys in the database, so nothing keeps the KMS from deleting a key a CA still uses.

This tool performs a one-shot, idempotent migration that reads CA certificates
and writes the missing records into the KMS.

> **Note (4.0.0)**: Since 4.0.0, Lamassu stores all services in the single
> `pki` PostgreSQL database, using one schema per service. This tool reads the
> `ca` schema and writes the `kms` schema of the `pki` database
> (`engines/storage/postgres` hardcodes `dbname=pki`). If your installation is
> still on 3.8.0 with per-service databases, transfer the data to the `pki`
> schemas first (see the upgrade guide) and run this tool only afterwards.

## What It Does

1. Connects to the PostgreSQL database using the standard storage config.
2. Reads all CA certificates of type `MANAGED` and `IMPORTED_WITH_KEY` from the
   `ca` schema.
3. Groups certificates by `subject_key_id`, in order.
4. For each key whose public key is not already present in the KMS storage in the same
   engine, whatever name it is stored under (its `subject_key_id`, the SHA-256 digest of
   its public key, or the `subject_key_id` of another certificate that shares the key):
   - Derives `algorithm`, `size`, and `public_key` from the X.509 certificate stored in the CA schema.
   - Sets `has_private_key = true` and `engine_id` from the certificate record.
5. Inserts the record into the KMS `kms_keys` table, with the `subject_key_id` as `key_id` (the name the crypto engine holds the key under) and the SHA-256 digest of its public key as `digest`. The table keeps a public key once per engine, so a key can no longer be registered twice under different names.

Certificates of type `IMPORTED_WITHOUT_KEY` are skipped because there is no private key to register.

A CA imported with its key since the KMS exists (3.7 and later) already has its key in the KMS
under the digest of its public key, while its `subject_key_id` is the one its issuer wrote. The
tool recognises that key by its digest and does not register it a second time under the
`subject_key_id`, which would add a row that no crypto engine holds.

Certificates of one engine can share a public key and carry different `subject_key_id`s, since
each is whatever its issuer wrote. The KMS stores a public key once per engine, so the tool
registers it once, under the lowest `subject_key_id`, and the other certificates find it. The
`ca` migration links them to that row by public key.

The operation is **idempotent**: if a key already exists in the KMS storage it is
skipped, so the tool can be run multiple times safely.

## Configuration

The tool reuses the standard KMS service config layout. Point the `LAMASSU_CONFIG_FILE` environment variable at a YAML file:

```yaml
logs:
  level: info   # debug | info | warn | error

storage:
  log_level: info
  provider: postgres
  hostname: <db-host>
  port: 5432
  username: <user>
  password: <password>
```

In 4.0.0 the `ca` and `kms` schemas live in the same `pki` database, so one
connection config is enough. The tool reads CA certificates from the `ca` schema
and writes key records to the `kms` schema.

> **Note**: The `hostname` field (not `host`) must be used.

## Usage

### Build

```bash
go build -o ca-to-kms-migration ./backend/cmd/ca-to-kms-migration/
```

### Dry run (no writes)

Run with `--dry-run` first to inspect what would be migrated without modifying
the KMS storage:

```bash
LAMASSU_CONFIG_FILE=migrate.yaml ./ca-to-kms-migration --dry-run
```

The output reports how many keys *would* be inserted and how many are already present.

### Actual migration

```bash
LAMASSU_CONFIG_FILE=migrate.yaml ./ca-to-kms-migration
```

The tool exits with code `0` on success and `1` if any key insertion failed, making it suitable for use as a Helm `pre-upgrade` hook.

### Example output

```
[INFO] found 3 unique keys across CA certificates
[INFO] key a3f1... — engine=filesystem-1 alg=RSA bits=2048 certificates=1
[INFO] key 9c2b... — engine=filesystem-1 alg=ECDSA bits=256 certificates=2
[INFO] key 77de... — engine=pkcs11-slot-0 alg=RSA bits=4096 certificates=1
[INFO] migration complete: inserted=3 skipped=0 failed=0
```

## Running as a Helm Pre-Upgrade Hook

The recommended way to run this migration in a Kubernetes environment is as a Helm `pre-upgrade` hook Job. The Job runs before Helm replaces any existing resources, ensuring the KMS database is populated before the new version of the services starts.

The tool applies no schema migration and registers every key with its `digest`, so it needs the `kms` schema already migrated; it stops with an error that says so otherwise. It must also run before the `ca` and `va` migrations, which need the keys it registers. The order is `kms` migration, this tool, `ca` migration, `va` migration. A chart that runs a single hook to migrate every schema cannot honour it: migrate the schemas one at a time (`goose-lamassu ... search_path=kms up`, and so on) and give this Job a hook weight between the `kms` migration and the `ca` one.

Create a `templates/ca-to-kms-migration-job.yaml` in your Helm chart:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: {{ include "lamassu.fullname" . }}-ca-to-kms-migration
  annotations:
    "helm.sh/hook": pre-upgrade
    "helm.sh/hook-weight": "-8"         # after the kms schema migration, before the ca and va ones
    "helm.sh/hook-delete-policy": before-hook-creation,hook-succeeded
spec:
  backoffLimit: 3
  template:
    metadata:
      name: ca-to-kms-migration
    spec:
      restartPolicy: OnFailure
      containers:
        - name: ca-to-kms-migration
          image: "{{ .Values.migration.image.repository }}:{{ .Values.migration.image.tag }}"
          imagePullPolicy: {{ .Values.migration.image.pullPolicy | default "IfNotPresent" }}
          env:
            - name: LAMASSU_CONFIG_FILE
              value: /etc/lamassu/migrate.yaml
          volumeMounts:
            - name: migration-config
              mountPath: /etc/lamassu
              readOnly: true
      volumes:
        - name: migration-config
          secret:
            secretName: {{ include "lamassu.fullname" . }}-ca-to-kms-migration-config
```

Store the config file as a Kubernetes Secret (keep the password out of plain-text values files):

```bash
kubectl create secret generic lamassu-ca-to-kms-migration-config \
  --from-file=migrate.yaml=./migrate.yaml \
  --namespace <your-namespace>
```

Relevant `values.yaml` additions:

```yaml
migration:
  image:
    repository: your-registry/ca-to-kms-migration
    tag: latest
    pullPolicy: IfNotPresent
```

On the next `helm upgrade` the Job will run automatically before any Deployment rollout. If the Job fails (exit code 1), Helm will mark the upgrade as failed and roll back.

## After the Upgrade: Rename Imported CA Keys to Their Digest

The KMS identifies every key by the SHA-256 of its public key (its `key_id`), and each certificate of the CA references its key by that value (`certificates.key_id`), so the database keeps the KMS from deleting a key a certificate uses. Crypto engines before the KMS renamed the key of an imported CA to its certificate's SKI instead, and this tool registers it under that name. Run this tool before validating the certificate-to-key foreign key. The CA migration resolves legacy SKI-named keys by their public key, so their certificates reference the real KMS key ID and protect it from deletion. Subsequent renames cascade to those references. A missing KMS key aborts the migration; it is never silently detached from its certificates.

The standalone KMS renames these keys when it starts with `crypto_engines.migrate_keys_format` enabled. For each key whose `key_id` is not the digest of its public key, it:

1. renames the key in its crypto engine;
2. changes its `key_id` in the KMS to the digest, keeping the old name as an alias, so anything that still refers to the key by its SKI finds it;
3. moves along the references of the certificates that use it.

Keys already named by their digest, keys without a private key, keys whose engine is not configured, and keys the engine also holds under their digest are left as they are and logged.

**Procedure**, once, after upgrading an installation that had imported CAs before 3.7:

1. Migrate the `kms` schema first, then run this tool to register legacy CA keys. Apply the `ca` migrations only after every referenced key exists. If validation reports an unresolved certificate key, register the missing key or repair its reference and retry. Finally migrate `va`, whose Roles reference existing certificates. The required order is `kms` → legacy key registration → `ca` → `va`.
2. Start the standalone KMS with the option enabled:
   ```yaml
   crypto_engines:
     migrate_keys_format: true
   ```
3. Check its log: it reports each renamed key (`renamed key <SKI> in engine <engine> to <digest>`) and how many it renamed, and warns about any key it left as it was.
4. Disable the option again. Running it again is safe: it finds nothing to rename, and finishes a rename that was interrupted.

A key left as it was keeps its name until the cause in the warning is fixed and the KMS starts again with the option enabled. If the engine also holds the key under its digest, remove one of the two copies by hand first.

## Running Tests

```bash
go test ./backend/pkg/migration/catokms/...
```

The tests use in-memory mock storage implementations and need no external dependencies, except `TestCheckKMSSchema` and `TestMigrateWithConfigRunsBeforeTheCASchemaIsMigrated`, which start a PostgreSQL container and need Docker.
