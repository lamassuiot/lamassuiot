-- +goose Up
-- +goose StatementBegin

-- The resources that use each engine's copy of a key. A key with bindings cannot be deleted:
-- the foreign key enforces it for every path, not only for the CA service.
CREATE TABLE key_bindings (
    key_id        text        NOT NULL,
    engine_id     text        NOT NULL,
    resource_type text        NOT NULL,
    resource_id   text        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT key_bindings_pkey PRIMARY KEY (key_id, engine_id, resource_type, resource_id),
    CONSTRAINT key_bindings_key_fk FOREIGN KEY (key_id, engine_id)
        REFERENCES kms_keys (key_id, engine_id) ON DELETE RESTRICT
);

CREATE INDEX key_bindings_resource_idx ON key_bindings (resource_type, resource_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE key_bindings;
-- +goose StatementEnd
