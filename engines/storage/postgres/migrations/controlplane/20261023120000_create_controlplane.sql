-- +goose Up
-- +goose StatementBegin
CREATE TABLE organizations (
	id text NOT NULL,
	name text NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now(),
	CONSTRAINT organizations_pkey PRIMARY KEY (id),
	CONSTRAINT organizations_name_key UNIQUE (name)
);

CREATE TABLE tenants (
	id text NOT NULL,
	organization_id text NOT NULL,
	installation_id text NOT NULL,
	name text NOT NULL,
	status text NOT NULL,
	isolation_mode text NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now(),
	deleted_at timestamptz NULL,
	CONSTRAINT tenants_pkey PRIMARY KEY (id),
	CONSTRAINT tenants_organization_fk FOREIGN KEY (organization_id) REFERENCES organizations (id),
	CONSTRAINT tenants_organization_name_key UNIQUE (organization_id, name),
	CONSTRAINT tenants_status_check CHECK (status IN ('ACTIVE', 'SUSPENDED', 'DELETED', 'RESTORING')),
	CONSTRAINT tenants_isolation_mode_check CHECK (isolation_mode IN ('POOLED', 'DEDICATED_DATABASE', 'DEDICATED_CRYPTO', 'FULLY_DEDICATED'))
);

INSERT INTO organizations (id, name)
VALUES ('00000000-0000-0000-0000-000000000001', 'Default Organization')
ON CONFLICT (id) DO NOTHING;

INSERT INTO tenants (id, organization_id, installation_id, name, status, isolation_mode)
VALUES (
	'00000000-0000-0000-0000-000000000002',
	'00000000-0000-0000-0000-000000000001',
	'default',
	'Default Tenant',
	'ACTIVE',
	'POOLED'
)
ON CONFLICT (id) DO NOTHING;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE tenants;
DROP TABLE organizations;
-- +goose StatementEnd