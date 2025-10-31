-- +goose Up
-- +goose StatementBegin
INSERT INTO kms_keys
(id, "name", algorithm, "size", public_key, status, creation_ts, metadata)
VALUES('pkcs11:token-id=fs-1;id=f14cdaff1d41b9ca38ca414f20d401612fca113de8dafbb0a2bc17d290a62d99;type=private', 'med', 'ECDSA', 384, 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVSdWhNc2RmZ2l0WTdMa2p3VFNjNzEvdXRpWE5IckJrWgpvb0g2eFd0d1hrSER5eTZCb1VIQ29lWlBidzA3cExkRnhrQ2FZQTZ6NWdzNHIrZ2ZNTGpDY3RoT094MnNSOWZsClRYV3ljZks2bk9tS3FadzRvampNK2RiU0Zjb1cwRSt3Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=', 'ACTIVE', '2025-10-03 08:30:18.401', NULL);-- +goose StatementEnd

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
    ADD COLUMN has_private_key boolean DEFAULT true;

-- 6️⃣ Drop old status column if no longer needed
ALTER TABLE kms_keys DROP COLUMN status;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 'down SQL query';
-- +goose StatementEnd
