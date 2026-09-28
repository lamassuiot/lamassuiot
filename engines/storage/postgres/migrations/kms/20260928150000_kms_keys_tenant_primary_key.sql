-- 003 T13: la PK de kms_keys pasa a (tenant_id, key_id) para que dos tenants puedan
-- registrar la misma clave (key_id = SHA-256 del SPKI). La UNIQUE (tenant_id, key_id)
-- queda redundante con la nueva PK y se retira; kms_keys_tenant_id_idx, las políticas RLS
-- y los permisos de lamassu_app no cambian.

-- +goose Up
-- +goose StatementBegin
ALTER TABLE kms_keys DROP CONSTRAINT keys_pkey;
ALTER TABLE kms_keys ADD CONSTRAINT keys_pkey PRIMARY KEY (tenant_id, key_id);
ALTER TABLE kms_keys DROP CONSTRAINT kms_keys_tenant_id_key;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- La PK global (key_id) no admite el mismo key_id en dos tenants: se aborta sin borrar
-- filas y el operador decide qué hacer con las claves repetidas.
DO $$
DECLARE
    duplicated text;
BEGIN
    SELECT string_agg(key_id, ', ' ORDER BY key_id) INTO duplicated
    FROM (SELECT key_id FROM kms_keys GROUP BY key_id HAVING count(*) > 1) AS d;
    IF duplicated IS NOT NULL THEN
        RAISE EXCEPTION 'no se puede restaurar PRIMARY KEY (key_id) en kms_keys: hay key_id repetidos entre tenants (%)', duplicated;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE kms_keys ADD CONSTRAINT kms_keys_tenant_id_key UNIQUE (tenant_id, key_id);
ALTER TABLE kms_keys DROP CONSTRAINT keys_pkey;
ALTER TABLE kms_keys ADD CONSTRAINT keys_pkey PRIMARY KEY (key_id);
-- +goose StatementEnd
