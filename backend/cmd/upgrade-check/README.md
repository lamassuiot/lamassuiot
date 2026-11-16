# Upgrade Check

## Motivation

Some v4 migrations refuse to run on data they cannot migrate safely: they abort and name the offending objects.
A migration stops at the first problem, so an operator who upgrades and hits one fixes it, retries, and may hit
the next one.

`upgrade-check` reports all of them **before** the upgrade, in one run. It only reads: it never writes database rows
or keys.

## When to run it

On the **3.8 database, after its data has been transferred to the schemas of the `pki` database** (see the upgrade
guide), and **before any v4 migration runs**. That means before deploying the v4 services or running
`lamassu-db-migration`.

The command refuses any other database and exits with code `2`: a database whose v4 VA migrations already ran
(`va.crl_settings` exists), or whose `va.va_role` is not the 3.8 one.

## What it checks

| Check | Reports | Migration it covers |
|---|---|---|
| `crypto engines` | every configured crypto engine that cannot start | — |
| `va signer` | VA roles whose CRL signer certificate cannot be resolved | `va/20261104121000_va_role_signer_certificate` |
| `va ca ids in urls` | CA ids containing `/` | `va/20261111120000_crl_settings` |
| `va shared ski` | VA roles whose SKI belongs to more than one CA | `va/20261111120000_crl_settings` |
| `va signer key` | VA roles whose signer certificate has no key | `va/20261111120000_crl_settings` |
| `va archived settings id` | CAs whose id is `legacy-<ski>` of a VA role whose CA was deleted | `va/20261111120000_crl_settings` |
| `va ambiguous crl urls` | CA ids equal to the SKI of another VA role | `va/20261111120000_crl_settings` |

Each problem uses the same wording as the migration that would abort, and names the CA ids, SKIs and serial numbers
to fix. The checks read the 3.8 schema and compute what the earlier v4 migrations derive from it, such as the
signer certificate of each VA role or whether its key can be found.

**Not covered yet**: the guards of `ca/20261008120000_unique_ca_id`, `ca/20261030120000_certificate_key_foreign_key`
and `kms/20260909084500_kms_key_composite_pk`. An all-clear means the migrations listed above will not abort, not
that the whole upgrade will pass. The report ends with the list of migrations the run covers.

### Crypto engines

The command starts every configured crypto engine, as the KMS does, so that later checks can reach the keys. No
check uses them yet. Starting an engine has the same side effects as starting the KMS, and no others:

- **Vault KV2** may auto-unseal Vault, when configured to, and creates its KV2 mount if it is missing.
- **Filesystem** creates its storage directory if it is missing.

No key is created, changed or deleted.

## Configuration

The command reuses the KMS service config. Point `LAMASSU_CONFIG_FILE` at a YAML file:

```yaml
logs:
  level: info   # debug | info | warn | error

storage:
  provider: postgres
  hostname: <db-host>
  port: 5432
  username: <user>
  password: <password>

crypto_engines:
  default_id: filesystem-1
  engines:
    - id: filesystem-1
      type: filesystem
      storage_directory: /crypto/fs
```

Only the `postgres` storage provider is supported. The `hostname` field (not `host`) must be used.

## Usage

```bash
go build -o upgrade-check ./backend/cmd/upgrade-check/
LAMASSU_CONFIG_FILE=upgrade-check.yaml ./upgrade-check
```

The image `ghcr.io/lamassuiot/lamassu-upgrade-check` runs the same command. It is built like the KMS image (CGO and
the PKCS#11 client libraries), so that it can start PKCS#11 engines.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Every check ran and found no problem. |
| `1` | Every check ran and at least one problem was found. |
| `2` | The command could not run (bad config, database unreachable, not a 3.8 database), or a check could not run. The problems the other checks found are still printed. |

### Example output

```
[crypto engines] ok
[va signer] ok
[va ca ids in urls] ok
[va shared ski] ok
[va signer key] ok
[va archived settings id] VA role 3f9a1c: CA legacy-3f9a1c has the id reserved for the archived settings of this role, whose CA was deleted. Recreate that CA with a different id before upgrading
[va ambiguous crl urls] ok

Covered migrations: va/20261104121000_va_role_signer_certificate, va/20261111120000_crl_settings
```
