-- RLS por tenant en event_outbox (003, referencia cruzada 006 T3): mismo patrón que
-- 20260921120000_enable_tenant_rls. lamassu_app recibe permisos sobre la tabla
-- solo junto con la política de aislamiento.
-- +goose Up
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE event_outbox TO lamassu_app;

ALTER TABLE event_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE event_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY event_outbox_tenant_isolation ON event_outbox
    FOR ALL TO lamassu_app
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- +goose Down
DROP POLICY IF EXISTS event_outbox_tenant_isolation ON event_outbox;
ALTER TABLE event_outbox DISABLE ROW LEVEL SECURITY;
ALTER TABLE event_outbox NO FORCE ROW LEVEL SECURITY;
REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLE event_outbox FROM lamassu_app;
