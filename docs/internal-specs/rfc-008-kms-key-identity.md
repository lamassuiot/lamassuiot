# RFC-008: KMS Key Identity

| Status | In progress |
|:---|:---|
| **Date** | 2026-11-24 |
| **Authors** | Engineering Team |
| **Focus** | KMS, CA Service, VA, `ca-to-kms-migration` |
| **Implementation Status** | Phase 1 (migration tool), Phase 2 (schema) and Phase 3a (resolution, aliases, API) done; Phase 3b (references) pending |

## 1. Abstract

A KMS key is identified today by `(key_id, engine_id)`, where `key_id` is the name the crypto engine gives the key. This RFC gives every key two identifiers that do not depend on the engine, a UUID `id` and the `digest` of its public key, and makes `key_id` (later `engine_key_id`) only the name of the object inside the engine.

## 2. Motivation

- **Keys that exist twice.** `ca-to-kms-migration` registered the key of each CA under the CA's `subject_key_id`. A CA imported with its key since 3.7 already has that key in the KMS under the digest of its public key, so the tool added a second row that no engine holds (`has_private_key = true`, nothing behind it). Signing with it fails, and deleting it answers "key not found".
- **Names that are not a digest.** Keys of CAs imported before the KMS are held by their engine under the SKI their issuer wrote. A SKI is not a function of the key and is not canonical (`aa:bb`, a serial number, 40 or 64 hex characters), so it cannot identify a key.
- **Lookups by SKI.** `VerifySignature` finds the key of a CA by its SKI, which stops working once the key is named by its digest.
- **No database guard.** Nothing stops a public key being stored twice in one engine.

## 3. Goals

1. A key has an `id` (UUID) assigned once and never changed, and a `digest` that is the hex SHA-256 of the DER SubjectPublicKeyInfo of its public key (64 characters).
2. Within an engine a public key is stored once: `UNIQUE (digest, engine_id)`.
3. A key is found by `id`, `digest` or alias. An alias can never be written in the form of an `id` or a `digest`.
4. The VA and the CA keep working: what references a key does so by `id`.
5. No migration needs to rename an object inside a crypto engine.

## 4. Non-Goals

- Renaming keys in the engines: `NormalizeKeyNames` does that, at startup and on demand.
- Removing `ca-to-kms-migration`: CAs managed or imported with a key before the KMS have no row in the KMS, and the `ca` migration needs one.

## 5. Design

### 5.1 `kms_keys`

| Column | Meaning |
|:---|:---|
| `id` uuid | Assigned by the database. Target of the references of `ca.certificates` and `va.crl_settings`. |
| `digest` text | Digest of the public key, checked against `^[0-9a-f]{64}$`. |
| `key_id` text | Name of the object in the crypto engine. Renamed `engine_key_id` in Phase 3. |

A key whose engine object is named by its SKI keeps that name until `NormalizeKeyNames` renames the object to its digest and keeps the SKI as an alias. Once every key is normalized the engine name is the digest, `engine_key_id` is redundant and a later migration drops it. The name is deliberately not stored as an alias: an alias is a list a user can edit, with no uniqueness in the database, and the engine name of a key must be exactly one value that nobody can lose.

### 5.2 Resolution

An identifier resolves, in this order, as:

1. a PKCS#11 URI (`pkcs11:token-id=<engine>;id=<name>;...`);
2. an `id`, when it has the shape of a UUID (any case);
3. a `digest`, when it has the shape of 64 hexadecimal digits (any case, compared in lowercase);
4. the name of the key in its engine (`key_id`), while that column exists;
5. an alias, but only when the identifier has neither of the shapes of steps 2 and 3.

A digest or a `key_id` held by several engines does not name a single key: the caller must give the `id` or the PKCS#11 URI, and gets `keyID is held by several engines` otherwise.

An identifier shaped like an id or a digest that matches nothing is "not found". It is never looked up as an alias: an alias of that shape would otherwise answer for a key that does not exist, and a client that asks for the key with a given digest could be handed another key. Step 4 stays for the keys an engine holds under their SKI, until `NormalizeKeyNames` renames them.

### 5.2.1 Aliases

`UpdateKeyAliases` refuses (`400`, `alias must not look like a key id (UUID), a key digest (64 hexadecimal digits) or a pkcs11 URI`) an alias that is a UUID, is 64 hexadecimal digits in either case, or starts with `pkcs11:`. It still refuses an alias equal to the `key_id` of any key, and one already in use. A SHA-256 digest has 64 hexadecimal digits; the 40 of a SHA-1 SKI are not a digest, so a SKI is a valid alias, which is how `NormalizeKeyNames` keeps the old name of a key it renames.

The `kms` migration drops the aliases already stored with an id or a digest shape: they could never be used again.

### 5.3 Phases

1. **Migration tool (done).** The tool also looks a key up by the digest of its public key in the engine and skips it when the KMS has it. CAs imported before the KMS are still registered under their SKI.
2. **Schema, additive (done).** Migration `kms/20261124100000_kms_key_identity.sql` adds `id` and `digest`, removes the duplicates the earlier tool left (keeping the row named by the digest, moving certificate and CRL-signer references to it, and keeping the aliases and the old name as aliases) and adds `UNIQUE (digest, engine_id)`. It stops, listing them, when it cannot tell which duplicate the engine holds, or when a public key cannot be read. The storage computes `digest` on insert. `id` and `digest` are not in the API yet.
3. **Resolution, aliases and API (done, 3a).** `GetKey` resolves as in 5.2 through two new storage lookups (`SelectExistsByID`, `SelectByDigest`), alias writes are validated as in 5.2.1, and `id` and `digest` are part of the API (`Key`, `kms-openapi.yaml`, `pki.json`). The HTTP client maps the errors of `GetKey` and `UpdateKeyAliases`.
4. **References (pending, 3b).** `ca.certificates.key_id` and `va.crl_settings.signer_key_id` become references to `kms_keys.id`; `key_id` is renamed `engine_key_id`; `VerifySignature` and the VA look keys up by reference and not by SKI; the migration tool follows.

The phases are separate commits of one change so that each leaves the repository passing its tests: renaming the column and moving the references change what the code writes, so they go with the code.

## 6. Backward Compatibility

Phase 2 is additive for readers of the table. Removing a duplicate row is not reversible by the `Down` migration; the row held nothing the survivor lacks. If the engine also held the key under the removed name, that copy stays in the engine, unreferenced.

## 7. Security Considerations

- A removed duplicate is only ever one the database can show to be redundant: the survivor is named by the digest and has a private key whenever the removed row has one. Anything else aborts the migration.
- Aliases merged into the survivor are checked against the `key_id` of every key, so a merged alias cannot start addressing another key.
- An id or a digest is never resolved through an alias (5.2), so nobody who can write aliases can make an identifier that names a key by its content answer with another key.
- The `digest` is derived from the stored public key, never taken from a client, and is not updatable.
- The migration uses fixed schema names and parameters in the dynamic statements.

## 8. Alternatives Considered

- **Rename `key_id` to `digest`.** Rows of keys held under their SKI would lose the name their engine knows them by.
- **Keep the engine name as an alias.** See 5.1.
- **Remove `ca-to-kms-migration`.** It removes the duplicates for CAs imported since 3.7 but leaves CAs older than the KMS without a key row, and the `ca` migration fails on them ("unresolved certificate key").

## 9. Open Questions

- Does the API keep a `key_id` field next to `id` and `digest` once `key_id` becomes `engine_key_id`, or expose only the new two? `id` and `digest` are already exposed next to `key_id`; this decides what happens to `key_id` in Phase 3b.
