-- +goose Up
-- +goose StatementBegin

-- The identity of a key is (key_id, engine_id): the same key_id can be held by several
-- engines at once (e.g. the private key in an offline HSM and the public key in an online
-- engine). 20251031174938_key.sql split the old PKCS#11-URI "id" column into key_id +
-- engine_id but kept the primary key on key_id alone, which makes that case unstorable.

-- Refuse to promote the key rather than inventing an identity for rows we cannot address.
DO $$
DECLARE orphans int;
BEGIN
    SELECT count(*) INTO orphans FROM kms_keys WHERE engine_id IS NULL OR engine_id = '';
    IF orphans > 0 THEN
        RAISE EXCEPTION 'cannot promote (key_id, engine_id) to primary key: % row(s) have no engine_id; backfill them before migrating', orphans;
    END IF;
END $$;

-- Identifiers now resolve as a key_id before an alias, so an alias equal to any key_id
-- would silently start addressing that other key. Earlier versions did not reject such
-- aliases; drop them rather than redirect signing, update or delete requests. This cannot
-- be undone by the Down migration.
DO $$
DECLARE shadowed text;
BEGIN
    SELECT string_agg(format('%s (on key %s in engine %s)', a.alias, k.key_id, k.engine_id), ', ')
    INTO shadowed
    FROM kms_keys AS k
    CROSS JOIN LATERAL jsonb_array_elements_text(
        CASE WHEN jsonb_typeof(k.aliases) = 'array' THEN k.aliases ELSE '[]'::jsonb END
    ) AS a(alias)
    WHERE EXISTS (SELECT 1 FROM kms_keys AS owner WHERE owner.key_id = a.alias);

    IF shadowed IS NULL THEN
        RETURN;
    END IF;

    RAISE NOTICE 'removing aliases that match an existing key_id: %', shadowed;

    UPDATE kms_keys AS k
    SET aliases = (
        SELECT COALESCE(jsonb_agg(a.alias ORDER BY a.ord), '[]'::jsonb)
        FROM jsonb_array_elements(k.aliases) WITH ORDINALITY AS a(alias, ord)
        WHERE NOT EXISTS (SELECT 1 FROM kms_keys AS owner WHERE owner.key_id = a.alias #>> '{}')
    )
    WHERE jsonb_typeof(k.aliases) = 'array'
      AND EXISTS (
        SELECT 1
        FROM jsonb_array_elements_text(
            CASE WHEN jsonb_typeof(k.aliases) = 'array' THEN k.aliases ELSE '[]'::jsonb END
        ) AS a(alias)
        JOIN kms_keys AS owner ON owner.key_id = a.alias
      );
END $$;

ALTER TABLE kms_keys ALTER COLUMN engine_id SET NOT NULL;
ALTER TABLE kms_keys DROP CONSTRAINT keys_pkey;
ALTER TABLE kms_keys ADD CONSTRAINT keys_pkey PRIMARY KEY (key_id, engine_id);

-- An alias is the other identifier that addresses a single key, so it is looked up on every
-- request that does not carry a PKCS#11 URI. jsonb_path_ops covers the containment operator
-- those lookups use and nothing else, which keeps the index smaller than the default class.
-- Note this does NOT enforce alias uniqueness: GIN has no unique indexes, and a unique index
-- cannot span the elements of an array.
CREATE INDEX kms_keys_aliases_idx ON kms_keys USING gin (aliases jsonb_path_ops);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Only reversible while no key_id is held by more than one engine.
DO $$
DECLARE duplicates int;
BEGIN
    SELECT count(*) INTO duplicates FROM (
        SELECT key_id FROM kms_keys GROUP BY key_id HAVING count(*) > 1
    ) d;
    IF duplicates > 0 THEN
        RAISE EXCEPTION 'cannot revert primary key to key_id: % key_id(s) are held by more than one engine', duplicates;
    END IF;
END $$;

DROP INDEX kms_keys_aliases_idx;
ALTER TABLE kms_keys DROP CONSTRAINT keys_pkey;
ALTER TABLE kms_keys ADD CONSTRAINT keys_pkey PRIMARY KEY (key_id);
ALTER TABLE kms_keys ALTER COLUMN engine_id DROP NOT NULL;

-- +goose StatementEnd
