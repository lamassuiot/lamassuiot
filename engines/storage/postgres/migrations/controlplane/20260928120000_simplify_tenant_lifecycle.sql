-- Ciclo de vida simplificado (002-327, decisión del 2026-09-28; 005-324 T10.1):
-- alta directa en ACTIVE y baja directa a DELETED, sin PROVISIONING ni DEPROVISIONING.
-- +goose Up
-- +goose StatementBegin
UPDATE tenants SET status = 'DELETED', deleted_at = COALESCE(deleted_at, now()) WHERE status = 'DEPROVISIONING';
UPDATE tenants SET status = 'SUSPENDED' WHERE status = 'PROVISIONING';

ALTER TABLE tenants DROP CONSTRAINT tenants_status_check;
ALTER TABLE tenants
	ADD CONSTRAINT tenants_status_check CHECK (status IN ('ACTIVE', 'SUSPENDED', 'DELETED', 'RESTORING'));
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Las filas convertidas no vuelven a su estado anterior: solo se restaura el CHECK.
ALTER TABLE tenants DROP CONSTRAINT tenants_status_check;
ALTER TABLE tenants
	ADD CONSTRAINT tenants_status_check CHECK (status IN ('PROVISIONING', 'ACTIVE', 'SUSPENDED', 'DEPROVISIONING', 'DELETED', 'RESTORING'));
-- +goose StatementEnd
