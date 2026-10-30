-- +goose Up
-- +goose StatementBegin
ALTER TABLE devices ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE device_groups ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE device_events ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE device_groups DROP CONSTRAINT IF EXISTS device_groups_name_key;
ALTER TABLE devices ADD CONSTRAINT devices_tenant_id_key UNIQUE (tenant_id, id);
ALTER TABLE device_groups ADD CONSTRAINT device_groups_tenant_id_key UNIQUE (tenant_id, id);
ALTER TABLE device_groups ADD CONSTRAINT device_groups_tenant_name_key UNIQUE (tenant_id, name);
ALTER TABLE device_groups ADD CONSTRAINT device_groups_tenant_parent_fk
	FOREIGN KEY (tenant_id, parent_id) REFERENCES device_groups (tenant_id, id);
ALTER TABLE device_events ADD CONSTRAINT device_events_tenant_device_fk
	FOREIGN KEY (tenant_id, device_id) REFERENCES devices (tenant_id, id) ON DELETE CASCADE;

CREATE INDEX devices_tenant_id_idx ON devices (tenant_id);
CREATE INDEX device_groups_tenant_id_idx ON device_groups (tenant_id);
CREATE INDEX device_events_tenant_id_idx ON device_events (tenant_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS device_events_tenant_id_idx;
DROP INDEX IF EXISTS device_groups_tenant_id_idx;
DROP INDEX IF EXISTS devices_tenant_id_idx;
ALTER TABLE device_events DROP CONSTRAINT IF EXISTS device_events_tenant_device_fk;
ALTER TABLE device_groups DROP CONSTRAINT IF EXISTS device_groups_tenant_parent_fk;
ALTER TABLE device_groups DROP CONSTRAINT IF EXISTS device_groups_tenant_name_key;
ALTER TABLE device_groups DROP CONSTRAINT IF EXISTS device_groups_tenant_id_key;
ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_tenant_id_key;
ALTER TABLE device_groups ADD CONSTRAINT device_groups_name_key UNIQUE (name);
ALTER TABLE device_events ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE device_groups ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE devices ALTER COLUMN tenant_id DROP NOT NULL;
-- +goose StatementEnd