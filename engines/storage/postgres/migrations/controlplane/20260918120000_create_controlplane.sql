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
	name text NOT NULL,
	status text NOT NULL,
	isolation_mode text NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now(),
	deleted_at timestamptz NULL,
	CONSTRAINT tenants_pkey PRIMARY KEY (id),
	CONSTRAINT tenants_organization_fk FOREIGN KEY (organization_id) REFERENCES organizations (id),
	CONSTRAINT tenants_organization_name_key UNIQUE (organization_id, name),
	CONSTRAINT tenants_id_organization_key UNIQUE (id, organization_id),
	CONSTRAINT tenants_status_check CHECK (status IN ('PROVISIONING', 'ACTIVE', 'SUSPENDED', 'DEPROVISIONING', 'DELETED', 'RESTORING')),
	CONSTRAINT tenants_isolation_mode_check CHECK (isolation_mode IN ('POOLED', 'DEDICATED_DATABASE', 'DEDICATED_CRYPTO', 'FULLY_DEDICATED'))
);

CREATE TABLE identities (
	issuer text NOT NULL,
	subject text NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now(),
	CONSTRAINT identities_pkey PRIMARY KEY (issuer, subject)
);

CREATE TABLE memberships (
	id text NOT NULL,
	organization_id text NOT NULL,
	tenant_id text NOT NULL,
	identity_issuer text NOT NULL,
	identity_subject text NOT NULL,
	role text NOT NULL,
	status text NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now(),
	CONSTRAINT memberships_pkey PRIMARY KEY (id),
	CONSTRAINT memberships_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (id),
	CONSTRAINT memberships_organization_fk FOREIGN KEY (organization_id) REFERENCES organizations (id),
	CONSTRAINT memberships_identity_fk FOREIGN KEY (identity_issuer, identity_subject) REFERENCES identities (issuer, subject),
	CONSTRAINT memberships_tenant_organization_fk FOREIGN KEY (tenant_id, organization_id) REFERENCES tenants (id, organization_id),
	CONSTRAINT memberships_identity_tenant_role_key UNIQUE (tenant_id, identity_issuer, identity_subject, role),
	CONSTRAINT memberships_role_check CHECK (role IN ('tenant_admin', 'pki_admin', 'operator', 'enroller', 'auditor', 'viewer')),
	CONSTRAINT memberships_status_check CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED'))
);

INSERT INTO organizations (id, name)
VALUES ('00000000-0000-0000-0000-000000000001', 'Default Organization')
ON CONFLICT (id) DO NOTHING;

INSERT INTO tenants (id, organization_id, name, status, isolation_mode)
VALUES (
	'00000000-0000-0000-0000-000000000002',
	'00000000-0000-0000-0000-000000000001',
	'Default Tenant',
	'ACTIVE',
	'POOLED'
)
ON CONFLICT (id) DO NOTHING;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE memberships;
DROP TABLE identities;
DROP TABLE tenants;
DROP TABLE organizations;
-- +goose StatementEnd