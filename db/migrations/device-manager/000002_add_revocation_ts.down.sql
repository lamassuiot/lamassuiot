BEGIN;

ALTER TABLE public.device_certificates_history DROP COLUMN revocation_ts;

COMMIT;