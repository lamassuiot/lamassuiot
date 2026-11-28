-- +goose Up
-- +goose StatementBegin

-- A key gets two identifiers that do not depend on how its crypto engine names it:
--   id      a UUID the database assigns, in lowercase canonical form; nothing about the key can change it. It is text
--           rather than the uuid type because the authorization policies filter it as a string.
--   digest  the hex SHA-256 of the DER SubjectPublicKeyInfo of its public key (64 characters), the name the KMS has
--           given the keys it creates since 3.7. Within an engine a public key is stored once, which the unique
--           (digest, engine_id) enforces.
-- key_id stays what it is: the name of the key inside its crypto engine. Keys of CAs imported before the KMS are held
-- under their SKI, and a SQL migration cannot rename an object in an HSM or a vault, so it keeps that name.

ALTER TABLE kms_keys
    ADD COLUMN id text NOT NULL DEFAULT gen_random_uuid()::text,
    ADD COLUMN digest text;

-- public_key is the base64 of a PEM "PUBLIC KEY" block. A key whose public key cannot be read is refused rather than
-- given an invented digest.
DO $$
DECLARE
    k record;
    pem text;
    bad text := '';
BEGIN
    FOR k IN SELECT key_id, engine_id, public_key FROM kms_keys ORDER BY engine_id, key_id LOOP
        BEGIN
            pem := convert_from(decode(k.public_key, 'base64'), 'UTF8');
            IF pem !~ '^\s*-----BEGIN PUBLIC KEY-----' THEN
                RAISE EXCEPTION 'not a PEM public key';
            END IF;
            UPDATE kms_keys
            SET digest = encode(sha256(decode(regexp_replace(pem, '-----[A-Z ]+-----|\s', '', 'g'), 'base64')), 'hex')
            WHERE key_id = k.key_id AND engine_id = k.engine_id;
        EXCEPTION WHEN OTHERS THEN
            bad := bad || format('%s%s (engine %s)', CASE WHEN bad = '' THEN '' ELSE ', ' END, k.key_id, k.engine_id);
        END;
    END LOOP;

    IF bad <> '' THEN
        RAISE EXCEPTION 'cannot compute the digest of the public key of: %. Repair or delete these keys before migrating', bad;
    END IF;
END $$;

-- The same public key stored twice in one engine. The migration tool of earlier versions registered the key of a CA
-- imported since the KMS exists under its SKI, next to the row the KMS had already created under its digest: the engine
-- never held that second name, so signing with it fails and deleting it reports "key not found".
-- The row named by the digest is the one the engine holds. The other is removed after what pointed at it is moved to
-- the survivor, which also keeps its aliases and its old name as an alias. Any other combination cannot be settled from
-- the database, so the migration stops and lists it.
DO $$
DECLARE
    grp record;
    survivor record;
    ghost record;
    ambiguous text := '';
    moved jsonb;
    -- A ca schema that has not run its migrations yet (a 3.8 database) has no key_id in ca.certificates: the CA migration
    -- that adds it also relinks every certificate to its key by public key. Only a reference that exists is moved.
    -- The catalog is read rather than information_schema, which hides the tables the migration user has no privilege on
    -- (each schema may be migrated by its own user).
    certificates_table oid := (SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'ca' AND c.relname = 'certificates' AND c.relkind = 'r');
    signer_table oid := (SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'va' AND c.relname = 'crl_settings' AND c.relkind = 'r');
    certificates_reference boolean := (SELECT count(*) = 2 FROM pg_attribute
        WHERE attrelid = certificates_table AND attname IN ('engine_id', 'key_id') AND NOT attisdropped);
    signer_reference boolean := (SELECT count(*) = 2 FROM pg_attribute
        WHERE attrelid = signer_table AND attname IN ('signer_engine_id', 'signer_key_id') AND NOT attisdropped);
BEGIN
    FOR grp IN
        SELECT digest, engine_id FROM kms_keys GROUP BY digest, engine_id HAVING count(*) > 1 ORDER BY engine_id, digest
    LOOP
        SELECT * INTO survivor FROM kms_keys WHERE digest = grp.digest AND engine_id = grp.engine_id AND key_id = grp.digest;
        IF NOT FOUND
           OR EXISTS (SELECT 1 FROM kms_keys
                      WHERE digest = grp.digest AND engine_id = grp.engine_id AND key_id <> grp.digest
                        AND has_private_key AND NOT survivor.has_private_key) THEN
            ambiguous := ambiguous || format('%s%s in engine %s', CASE WHEN ambiguous = '' THEN '' ELSE '; ' END, grp.digest, grp.engine_id);
        END IF;
    END LOOP;

    IF ambiguous <> '' THEN
        RAISE EXCEPTION 'several keys with the same public key in one engine, none of them a name the engine certainly holds: %. Delete the copies the engine does not hold before migrating (the digest of the public key is the name the KMS gives a key)', ambiguous;
    END IF;

    FOR grp IN
        SELECT digest, engine_id FROM kms_keys GROUP BY digest, engine_id HAVING count(*) > 1 ORDER BY engine_id, digest
    LOOP
        FOR ghost IN SELECT * FROM kms_keys WHERE digest = grp.digest AND engine_id = grp.engine_id AND key_id <> grp.digest LOOP
            RAISE NOTICE 'removing key % of engine %: it is the public key of %, which the engine holds under that name', ghost.key_id, ghost.engine_id, grp.digest;

            -- has_table_privilege with a list of privileges answers whether ANY of them is held: each is checked alone
            IF certificates_reference AND NOT (has_schema_privilege('ca', 'USAGE') AND has_table_privilege(certificates_table, 'SELECT') AND has_table_privilege(certificates_table, 'UPDATE')) THEN
                RAISE EXCEPTION 'removing the duplicate key % of engine % moves the references of ca.certificates to %, and the migration user lacks USAGE on schema ca or SELECT, UPDATE on ca.certificates. Grant them before migrating',
                    ghost.key_id, ghost.engine_id, grp.digest;
            END IF;
            IF signer_reference AND NOT (has_schema_privilege('va', 'USAGE') AND has_table_privilege(signer_table, 'SELECT') AND has_table_privilege(signer_table, 'UPDATE')) THEN
                RAISE EXCEPTION 'removing the duplicate key % of engine % moves the references of va.crl_settings to %, and the migration user lacks USAGE on schema va or SELECT, UPDATE on va.crl_settings. Grant them before migrating',
                    ghost.key_id, ghost.engine_id, grp.digest;
            END IF;
            IF certificates_reference THEN
                EXECUTE 'UPDATE ca.certificates SET key_id = $1 WHERE engine_id = $2 AND key_id = $3'
                    USING grp.digest, ghost.engine_id, ghost.key_id;
            END IF;
            IF signer_reference THEN
                EXECUTE 'UPDATE va.crl_settings SET signer_key_id = $1 WHERE signer_engine_id = $2 AND signer_key_id = $3'
                    USING grp.digest, ghost.engine_id, ghost.key_id;
            END IF;

            DELETE FROM kms_keys WHERE key_id = ghost.key_id AND engine_id = ghost.engine_id;

            -- Identifiers resolve as a key_id before an alias, so an alias equal to the key_id of another key would
            -- be shadowed: leave out the names some key still has.
            SELECT COALESCE(jsonb_agg(DISTINCT a.alias), '[]'::jsonb) INTO moved
            FROM (
                SELECT jsonb_array_elements_text(CASE WHEN jsonb_typeof(aliases) = 'array' THEN aliases ELSE '[]'::jsonb END) AS alias
                FROM kms_keys WHERE key_id = grp.digest AND engine_id = grp.engine_id
                UNION
                SELECT jsonb_array_elements_text(CASE WHEN jsonb_typeof(ghost.aliases) = 'array' THEN ghost.aliases ELSE '[]'::jsonb END)
                UNION
                SELECT ghost.key_id
            ) AS a
            WHERE NOT EXISTS (SELECT 1 FROM kms_keys WHERE key_id = a.alias);

            UPDATE kms_keys SET aliases = moved WHERE key_id = grp.digest AND engine_id = grp.engine_id;
        END LOOP;
    END LOOP;
END $$;

-- An identifier shaped like an id (a UUID) or a digest (64 hexadecimal digits) is read as that and never looked up as
-- an alias, and such aliases are refused from now on. Earlier versions accepted them, so the ones stored could never be
-- used again: drop them rather than leave names that answer to nothing. This cannot be undone by the Down migration.
DO $$
DECLARE dead text;
BEGIN
    SELECT string_agg(format('%s (on key %s in engine %s)', a.alias, k.key_id, k.engine_id), ', ')
    INTO dead
    FROM kms_keys AS k
    CROSS JOIN LATERAL jsonb_array_elements_text(
        CASE WHEN jsonb_typeof(k.aliases) = 'array' THEN k.aliases ELSE '[]'::jsonb END
    ) AS a(alias)
    WHERE a.alias ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR a.alias ~* '^[0-9a-f]{64}$';

    IF dead IS NULL THEN
        RETURN;
    END IF;

    RAISE NOTICE 'removing aliases shaped like a key id or a digest: %', dead;

    UPDATE kms_keys AS k
    SET aliases = (
        SELECT COALESCE(jsonb_agg(a.alias ORDER BY a.ord), '[]'::jsonb)
        FROM jsonb_array_elements(k.aliases) WITH ORDINALITY AS a(alias, ord)
        WHERE NOT ((a.alias #>> '{}') ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                OR (a.alias #>> '{}') ~* '^[0-9a-f]{64}$')
    )
    WHERE jsonb_typeof(k.aliases) = 'array'
      AND EXISTS (
        SELECT 1 FROM jsonb_array_elements_text(k.aliases) AS a(alias)
        WHERE a.alias ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR a.alias ~* '^[0-9a-f]{64}$'
      );
END $$;

ALTER TABLE kms_keys ALTER COLUMN digest SET NOT NULL;
ALTER TABLE kms_keys ADD CONSTRAINT kms_keys_digest_format CHECK (digest ~ '^[0-9a-f]{64}$');
ALTER TABLE kms_keys ADD CONSTRAINT kms_keys_id_format
    CHECK (id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$');
ALTER TABLE kms_keys ADD CONSTRAINT kms_keys_digest_engine_key UNIQUE (digest, engine_id);
-- the target later references to a key point at
ALTER TABLE kms_keys ADD CONSTRAINT kms_keys_id_key UNIQUE (id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- The rows removed as duplicates, the references moved to the surviving row and the aliases dropped are not restored.
ALTER TABLE kms_keys DROP CONSTRAINT kms_keys_id_key;
ALTER TABLE kms_keys DROP CONSTRAINT kms_keys_digest_engine_key;
ALTER TABLE kms_keys DROP CONSTRAINT kms_keys_id_format;
ALTER TABLE kms_keys DROP CONSTRAINT kms_keys_digest_format;
ALTER TABLE kms_keys DROP COLUMN digest, DROP COLUMN id;

-- +goose StatementEnd
