-- +goose Up
-- +goose StatementBegin
ALTER TABLE memberships DROP CONSTRAINT memberships_identity_tenant_role_key;
ALTER TABLE memberships
	ADD CONSTRAINT memberships_identity_tenant_key UNIQUE (tenant_id, identity_issuer, identity_subject);

CREATE TABLE invitations (
	id text NOT NULL,
	organization_id text NOT NULL,
	tenant_id text NOT NULL,
	role text NOT NULL,
	code_hash text NOT NULL,
	status text NOT NULL,
	created_by_issuer text NOT NULL,
	created_by_subject text NOT NULL,
	expires_at timestamptz NOT NULL,
	accepted_by_issuer text NULL,
	accepted_by_subject text NULL,
	accepted_at timestamptz NULL,
	created_at timestamptz NOT NULL DEFAULT now(),
	CONSTRAINT invitations_pkey PRIMARY KEY (id),
	CONSTRAINT invitations_code_hash_key UNIQUE (code_hash),
	CONSTRAINT invitations_tenant_organization_fk FOREIGN KEY (tenant_id, organization_id) REFERENCES tenants (id, organization_id),
	CONSTRAINT invitations_role_check CHECK (role IN ('tenant_admin', 'pki_admin', 'operator', 'enroller', 'auditor', 'viewer')),
	CONSTRAINT invitations_status_check CHECK (status IN ('PENDING', 'ACCEPTED', 'REVOKED')),
	CONSTRAINT invitations_accepted_check CHECK (
		(status = 'ACCEPTED') = (accepted_at IS NOT NULL AND accepted_by_issuer IS NOT NULL AND accepted_by_subject IS NOT NULL)
	)
);

CREATE INDEX invitations_tenant_idx ON invitations (tenant_id, created_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE invitations;
ALTER TABLE memberships DROP CONSTRAINT memberships_identity_tenant_key;
ALTER TABLE memberships
	ADD CONSTRAINT memberships_identity_tenant_role_key UNIQUE (tenant_id, identity_issuer, identity_subject, role);
-- +goose StatementEnd
