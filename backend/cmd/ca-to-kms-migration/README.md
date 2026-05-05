# CA-to-KMS Key Migration Tool

## Motivation

The KMS service was introduced as an independent service in version 3.7.0 of Lamassu IoT. In earlier versions, private keys were managed exclusively by the crypto engine (filesystem, PKCS#11, Vault KV2, AWS KMS, etc.) and there was no separate KMS database table to track them.

When upgrading from an older installation, each CA certificate of type `MANAGED` or `IMPORTED_WITH_KEY` has a private key stored in the crypto engine under its `subject_key_id`. That key has no corresponding row in the `kms_keys` table of the KMS database. As a result:

- The KMS service is unaware of those keys and cannot manage, list, or bind them.
- The `lamassu.io/kms/binded-resources` metadata — which records which CA certificates are bound to a given key — is absent.

This tool performs a one-shot, idempotent migration that reads the CA database and writes the missing records into the KMS database.

## What It Does

1. Connects to the CA Postgres database (read-only).
2. Scans all CA certificates of type `MANAGED` and `IMPORTED_WITH_KEY`.
3. Groups certificates that share the same public key (same `subject_key_id`).
4. For each unique key not already present in the KMS database:
   - Derives `algorithm`, `size`, and `public_key` from the X.509 certificate stored in the CA database.
   - Sets `has_private_key = true` and `engine_id` from the certificate record.
   - Populates `metadata["lamassu.io/kms/binded-resources"]` with the serial numbers of all CA certificates that use the key.
5. Inserts the record into the KMS `kms_keys` table.

Certificates of type `IMPORTED_WITHOUT_KEY` are skipped because there is no private key to register.

The operation is **idempotent**: if a key already exists in the KMS database it is skipped, so the tool can be run multiple times safely.

## Configuration

The tool uses the same config-loading mechanism as all other Lamassu services. Point the `LAMASSU_CONFIG_FILE` environment variable at a YAML file with the following structure:

```yaml
log_level: info   # debug | info | warn | error

ca_storage:
  provider: postgres
  hostname: <ca-db-host>
  port: 5432
  username: <user>
  password: <password>

kms_storage:
  provider: postgres
  hostname: <kms-db-host>
  port: 5432
  username: <user>
  password: <password>
```

> **Note**: The `hostname` field (not `host`) must be used. The database name is fixed internally: the CA engine always connects to the `ca` database and the KMS engine always connects to the `kms` database.

## Usage

### Build

```bash
go build -o ca-to-kms-migration ./backend/cmd/ca-to-kms-migration/
```

### Dry run (no writes)

Run with `--dry-run` first to inspect what would be migrated without modifying the KMS database:

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
[INFO] key a3f1... — engine=filesystem-1 alg=RSA bits=2048 binds=1
[INFO] key 9c2b... — engine=filesystem-1 alg=ECDSA bits=256 binds=2
[INFO] key 77de... — engine=pkcs11-slot-0 alg=RSA bits=4096 binds=1
[INFO] migration complete: inserted=3 skipped=0 failed=0
```

## Running as a Helm Pre-Upgrade Hook

The recommended way to run this migration in a Kubernetes environment is as a Helm `pre-upgrade` hook Job. The Job runs before Helm replaces any existing resources, ensuring the KMS database is populated before the new version of the services starts.

Create a `templates/ca-to-kms-migration-job.yaml` in your Helm chart:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: {{ include "lamassu.fullname" . }}-ca-to-kms-migration
  annotations:
    "helm.sh/hook": pre-upgrade
    "helm.sh/hook-weight": "-10"        # run before other pre-upgrade hooks
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

## Running Tests

```bash
go test ./backend/pkg/migration/catokms/...
```

The tests use in-memory mock storage implementations and require no external dependencies (no Docker, no database).
