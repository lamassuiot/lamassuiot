-- RLS por tenant en event_outbox (003, referencia cruzada 006 T3): lamassu_app ya
-- tiene permisos sobre la tabla (20260928130000_grant_lamassu_app) y debe cumplir
-- el mismo aislamiento que el resto de tablas por tenant.
-- +goose Up
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
