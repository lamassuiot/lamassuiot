-- Permisos del rol de aplicación sin privilegios sobre controlplane (005-324 T10.1):
-- sin ellos el Tenant Manager responde 500 al conectar como lamassu_app.
-- Las tablas de controlplane no usan secuencias (claves text), así que no hay GRANT de USAGE.
-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'lamassu_app') THEN
        CREATE ROLE lamassu_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
    END IF;
END
$$;
-- +goose StatementEnd

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE organizations, tenants, identities, memberships, invitations, dedicated_crypto_selectors, event_outbox TO lamassu_app;

-- +goose Down
REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLE organizations, tenants, identities, memberships, invitations, dedicated_crypto_selectors, event_outbox FROM lamassu_app;
