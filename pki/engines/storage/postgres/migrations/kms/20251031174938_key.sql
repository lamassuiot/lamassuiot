-- +goose Up
-- +goose StatementBegin
ALTER TABLE kms_keys
    ADD COLUMN engine_id text,
    ADD COLUMN key_id text;

-- 2️⃣ Populate key_id and engine_id by parsing the old id column
UPDATE kms_keys
SET
    engine_id = regexp_replace(id, '^pkcs11:token-id=([^;]+);.*$', '\1'),
    key_id = regexp_replace(id, '^.*id=([0-9a-f]+);.*$', '\1');

-- 3️⃣ Drop the old id column and set key_id as the new primary key
ALTER TABLE kms_keys DROP CONSTRAINT keys_pkey;
ALTER TABLE kms_keys DROP COLUMN id;
ALTER TABLE kms_keys ADD CONSTRAINT keys_pkey PRIMARY KEY (key_id);

-- 4️⃣ Convert metadata to JSONB (if not already)
ALTER TABLE kms_keys
    ALTER COLUMN metadata TYPE jsonb
    USING metadata::jsonb;

-- 5️⃣ Add any missing new columns from your Go struct
ALTER TABLE kms_keys
    ADD COLUMN aliases jsonb DEFAULT '[]'::jsonb,
    ADD COLUMN has_private_key boolean DEFAULT true,
    ADD COLUMN tags jsonb DEFAULT '[]'::jsonb;

-- 6️⃣ Drop old status column if no longer needed
ALTER TABLE kms_keys DROP COLUMN status;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 'down SQL query';
-- +goose StatementEnd
