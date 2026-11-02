-- +goose Up
-- +goose StatementBegin
ALTER TABLE kms_keys ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE kms_keys DROP CONSTRAINT keys_pkey;
ALTER TABLE kms_keys ADD CONSTRAINT keys_pkey PRIMARY KEY (tenant_id, key_id, engine_id);
CREATE INDEX kms_keys_tenant_id_idx ON kms_keys (tenant_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$
DECLARE duplicates int;
BEGIN
    SELECT count(*) INTO duplicates FROM (
        SELECT key_id, engine_id FROM kms_keys GROUP BY key_id, engine_id HAVING count(*) > 1
    ) d;
    IF duplicates > 0 THEN
        RAISE EXCEPTION 'cannot revert primary key to (key_id, engine_id): % key(s) are held by more than one tenant', duplicates;
    END IF;
END $$;

DROP INDEX IF EXISTS kms_keys_tenant_id_idx;
ALTER TABLE kms_keys DROP CONSTRAINT keys_pkey;
ALTER TABLE kms_keys ADD CONSTRAINT keys_pkey PRIMARY KEY (key_id, engine_id);
ALTER TABLE kms_keys ALTER COLUMN tenant_id DROP NOT NULL;
-- +goose StatementEnd